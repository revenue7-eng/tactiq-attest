//! TPM access for the prover.
//!
//! This layer shells out to tpm2-tools. That is a deliberate Phase 0 choice,
//! not the end state:
//!
//!   * the command sequence is identical to `attest-core/run.sh`, which is the
//!     sequence already proven end-to-end against the verifier, so the first
//!     agent cannot drift from the harness that validated the protocol;
//!   * it behaves the same against swtpm and against a discrete chip, so the
//!     agent can be finished before the TPM module arrives;
//!   * every TPM call lives here and nowhere else, so replacing it with
//!     tss-esapi later touches one file.
//!
//! Consequence to be honest about: while this layer is in use, the production
//! image must ship tpm2-tools, not just the libtss2 runtime. Swapping to
//! tss-esapi removes that dependency and is the reason this module exists as a
//! seam rather than as calls scattered through main.

use std::path::Path;
use std::process::Command;

/// Owner-hierarchy persistent handle for the primary (parent) key.
pub const PARENT_HANDLE: &str = "0x81010001";
/// Owner-hierarchy persistent handle for the attestation signing key.
pub const KEY_HANDLE: &str = "0x81010002";
/// NV index holding the monotonic counter that provides freshness.
pub const NV_COUNTER: &str = "0x1500016";

pub type R<T> = Result<T, String>;

fn run(args: &[&str]) -> R<Vec<u8>> {
    let out = Command::new(args[0])
        .args(&args[1..])
        .output()
        .map_err(|e| format!("{}: {e}", args[0]))?;
    if !out.status.success() {
        return Err(format!(
            "{} failed ({}): {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}

/// True when the handle is already occupied in the owner hierarchy.
pub fn handle_exists(handle: &str) -> bool {
    match run(&["tpm2_getcap", "handles-persistent"]) {
        Ok(o) => String::from_utf8_lossy(&o).contains(handle),
        Err(_) => false,
    }
}

/// True when the NV counter index is already defined.
pub fn nv_defined(index: &str) -> bool {
    match run(&["tpm2_getcap", "handles-nv-index"]) {
        Ok(o) => String::from_utf8_lossy(&o).contains(index),
        Err(_) => false,
    }
}

/// Create the primary key and persist it at `PARENT_HANDLE`.
pub fn create_primary(work: &Path) -> R<()> {
    let ctx = work.join("primary.ctx");
    let ctx = ctx.to_string_lossy().to_string();
    run(&["tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "ecc", "-c", &ctx])?;
    run(&["tpm2_evictcontrol", "-C", "o", "-c", &ctx, PARENT_HANDLE])?;
    let _ = run(&["tpm2_flushcontext", "-t"]);
    Ok(())
}

/// Create the ECDSA P-256 attestation key under the primary and persist it.
///
/// The key is restricted to the TPM (`tpm2_create` never emits the private
/// part in the clear) but is deliberately NOT sealed to a PCR policy.
///
/// Sealing would mean a device in an un-enrolled state could not sign at all.
/// The verifier would then observe silence rather than a signed attestation of
/// a state it does not recognise — and `verifier-rats` distinguishes
/// `UnrecognizedState` (device honestly attested something not in the golden
/// set) from `SignatureFail` (forgery) precisely so the consumer can quarantine
/// in one case and alarm in the other. A PCR-sealed signing key collapses that
/// distinction, and also makes a compromised device indistinguishable from one
/// that is merely powered off.
pub fn create_signing_key(work: &Path) -> R<()> {
    let pubf = work.join("key.pub");
    let privf = work.join("key.priv");
    let ctx = work.join("key.ctx");
    let (pubf, privf, ctx) = (
        pubf.to_string_lossy().to_string(),
        privf.to_string_lossy().to_string(),
        ctx.to_string_lossy().to_string(),
    );
    run(&[
        "tpm2_create", "-C", PARENT_HANDLE, "-G", "ecc256:ecdsa-sha256",
        "-u", &pubf, "-r", &privf,
    ])?;
    run(&["tpm2_load", "-C", PARENT_HANDLE, "-u", &pubf, "-r", &privf, "-c", &ctx])?;
    // Persisting the key means the signing path needs no transient load per
    // cycle: one TPM object, reused for the life of the device.
    run(&["tpm2_evictcontrol", "-C", "o", "-c", &ctx, KEY_HANDLE])?;
    let _ = run(&["tpm2_flushcontext", "-t"]);
    Ok(())
}

/// Read the persisted attestation key's public part as SubjectPublicKeyInfo PEM.
/// This is what the verifier loads into its trust store; it replaces a CA.
pub fn read_public_pem(out: &Path) -> R<()> {
    let out = out.to_string_lossy().to_string();
    run(&["tpm2_readpublic", "-c", KEY_HANDLE, "-f", "pem", "-o", &out])?;
    Ok(())
}

/// Define the monotonic counter. A TPM NV counter can be incremented and read
/// but never set or rolled back, which is what makes freshness work without a
/// nonce, a clock, or a network round trip.
pub fn nv_define() -> R<()> {
    run(&[
        "tpm2_nvdefine", NV_COUNTER, "-C", "o",
        "-a", "nt=counter|ownerread|ownerwrite",
    ])?;
    // A freshly defined counter is not readable until first increment.
    run(&["tpm2_nvincrement", NV_COUNTER, "-C", "o"])?;
    Ok(())
}

/// Advance the counter and return its new value.
///
/// Increment happens before the read, so the value in the envelope is one the
/// TPM can never produce again. Two cycles cannot share a counter value even if
/// they race.
pub fn nv_increment_and_read(work: &Path) -> R<u64> {
    run(&["tpm2_nvincrement", NV_COUNTER, "-C", "o"])?;
    let f = work.join("counter.bin");
    let fs_ = f.to_string_lossy().to_string();
    run(&["tpm2_nvread", NV_COUNTER, "-C", "o", "-o", &fs_])?;
    let raw = std::fs::read(&f).map_err(|e| format!("read counter: {e}"))?;
    if raw.len() != 8 {
        return Err(format!("counter is {} bytes, expected 8", raw.len()));
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&raw);
    Ok(u64::from_be_bytes(b))
}

/// Read the selected PCRs, returning the raw concatenated bank contents.
/// `spec` is a tpm2-tools selection string such as `sha256:0,1,2,3,4,5,6,7`.
///
/// The raw bytes are returned rather than a digest: hashing is done by
/// `attest-core::build_canonical`, so prover and verifier agree on the
/// composite by construction instead of by convention.
pub fn pcr_read(spec: &str, work: &Path) -> R<Vec<u8>> {
    let f = work.join("pcrs.bin");
    let fs_ = f.to_string_lossy().to_string();
    run(&["tpm2_pcrread", spec, "-o", &fs_])?;
    std::fs::read(&f).map_err(|e| format!("read pcrs: {e}"))
}

/// Parse a tpm2-tools PCR selection string into the (alg_id, bitmap) pair the
/// envelope encodes (`attest_envelope::encode_pcr_selection`).
///
/// This is the only place the declared selection is derived from, and it is
/// derived from the very string `pcr_read` hands to `tpm2_pcrread`, so the
/// declared selection and the attested contents cannot diverge
/// (tactiq-attest#1). Agreement by construction, not by convention.
///
/// Fail-closed, each rule tested:
///   * one bank only — the 5-byte selection cannot express a `+` multi-bank list;
///   * a known algorithm (TCG alg ids);
///   * PCR indices 0..=23 (a 3-byte bitmap covers exactly 24 PCRs);
///   * strictly ascending, no duplicates — one set has one canonical spelling.
pub fn parse_pcr_spec(spec: &str) -> R<(u16, [u8; 3])> {
    if spec.contains('+') {
        return Err(format!(
            "pcr spec `{spec}`: multi-bank selection cannot be encoded in the envelope"
        ));
    }
    let (alg, list) = spec
        .split_once(':')
        .ok_or_else(|| format!("pcr spec `{spec}`: expected `<alg>:<pcr,...>`"))?;
    let alg_id: u16 = match alg.trim() {
        "sha1" => 0x0004,
        "sha256" => 0x000B,
        "sha384" => 0x000C,
        "sha512" => 0x000D,
        other => return Err(format!("pcr spec `{spec}`: unknown algorithm `{other}`")),
    };
    let mut bitmap = [0u8; 3];
    let mut last: Option<u8> = None;
    for tok in list.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            return Err(format!("pcr spec `{spec}`: empty PCR index"));
        }
        let n: u8 = tok
            .parse()
            .map_err(|_| format!("pcr spec `{spec}`: bad PCR index `{tok}`"))?;
        if n > 23 {
            return Err(format!("pcr spec `{spec}`: PCR {n} out of range 0..=23"));
        }
        if let Some(p) = last {
            if n <= p {
                return Err(format!(
                    "pcr spec `{spec}`: PCR indices must be strictly ascending (got {n} after {p})"
                ));
            }
        }
        bitmap[(n / 8) as usize] |= 1 << (n % 8);
        last = Some(n);
    }
    if last.is_none() {
        return Err(format!("pcr spec `{spec}`: no PCRs selected"));
    }
    Ok((alg_id, bitmap))
}

/// Sign the canonical envelope with the persisted attestation key.
///
/// `-f plain` yields a bare r||s signature, which is what the verifier's
/// P-256 path expects; `-g sha256` matches the key's signing scheme.
pub fn sign(msg: &Path, sig: &Path) -> R<()> {
    let (m, s) = (msg.to_string_lossy().to_string(), sig.to_string_lossy().to_string());
    run(&["tpm2_sign", "-c", KEY_HANDLE, "-g", "sha256", "-f", "plain", "-o", &s, &m])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_pcr_spec;

    #[test]
    fn default_bank_and_pcrs_0_7() {
        assert_eq!(parse_pcr_spec("sha256:0,1,2,3,4,5,6,7").unwrap(), (0x000B, [0xff, 0x00, 0x00]));
    }

    #[test]
    fn algorithm_ids_follow_tcg_registry() {
        assert_eq!(parse_pcr_spec("sha1:0").unwrap().0, 0x0004);
        assert_eq!(parse_pcr_spec("sha384:0").unwrap().0, 0x000C);
        assert_eq!(parse_pcr_spec("sha512:0").unwrap().0, 0x000D);
    }

    #[test]
    fn bitmap_is_tpm_bit_order_across_all_three_bytes() {
        // PCR n -> byte n/8, bit n%8
        assert_eq!(parse_pcr_spec("sha256:8,15").unwrap().1, [0x00, 0x81, 0x00]);
        assert_eq!(parse_pcr_spec("sha256:16,23").unwrap().1, [0x00, 0x00, 0x81]);
        assert_eq!(parse_pcr_spec("sha256:0,23").unwrap().1, [0x01, 0x00, 0x80]);
    }

    #[test]
    fn rejects_out_of_range_pcr() {
        assert!(parse_pcr_spec("sha256:24").is_err());
        assert!(parse_pcr_spec("sha256:0,99").is_err());
    }

    #[test]
    fn rejects_multi_bank_because_envelope_cannot_encode_it() {
        assert!(parse_pcr_spec("sha1:0,1+sha256:0,1").is_err());
    }

    #[test]
    fn rejects_unknown_algorithm_and_missing_bank() {
        assert!(parse_pcr_spec("md5:0").is_err());
        assert!(parse_pcr_spec("0,1,2").is_err());
    }

    #[test]
    fn rejects_duplicates_and_non_ascending_for_one_canonical_spelling() {
        assert!(parse_pcr_spec("sha256:0,0").is_err());
        assert!(parse_pcr_spec("sha256:1,0").is_err());
    }

    #[test]
    fn rejects_empty_selection_and_empty_index() {
        assert!(parse_pcr_spec("sha256:").is_err());
        assert!(parse_pcr_spec("sha256:0,,1").is_err());
        assert!(parse_pcr_spec("sha256:0,").is_err());
    }
}
