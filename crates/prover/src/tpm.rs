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

/// Persistent handle of the attestation key (AK), DDR-005 decision 4.
///
/// The AK is a non-primary key in the endorsement hierarchy, so it sits above
/// the first 256 handles of the endorsement range, which the TCG registry keeps
/// for primaries such as the EK. Earlier agents persisted their own objects at
/// `0x81010001` (owner primary), `0x81010002` (v1 key) and `0x81010003` (v2 AK
/// under that primary); the first two are EK handles by convention. This agent
/// never reads, writes or evicts any of the three. Removing them from a device
/// is a separate, announced step.
///
/// A handle is never trusted by occupancy: every use of the object here is
/// preceded by `verify_ak`, which compares its name with the one recorded at
/// provisioning.
pub const AK_HANDLE: &str = "0x81010100";
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

/// True when `handle` appears in a `tpm2_getcap handles-*` listing.
///
/// Exact match per line (`- 0x81010100`), case-insensitive, not a substring
/// search over the whole output.
fn listing_has(listing: &str, handle: &str) -> bool {
    listing
        .lines()
        .filter_map(|l| l.trim().strip_prefix("- "))
        .any(|h| h.trim().eq_ignore_ascii_case(handle))
}

/// Whether the persistent handle is occupied. A failed `tpm2_getcap` is an
/// error, not "free": the caller decides on an answer it can trust.
pub fn handle_exists(handle: &str) -> R<bool> {
    let o = run(&["tpm2_getcap", "handles-persistent"])?;
    Ok(listing_has(&String::from_utf8_lossy(&o), handle))
}

/// Whether the NV counter index is defined. Errors as `handle_exists`.
pub fn nv_defined(index: &str) -> R<bool> {
    let o = run(&["tpm2_getcap", "handles-nv-index"])?;
    Ok(listing_has(&String::from_utf8_lossy(&o), index))
}

/// Recreate the RSA-2048 EK from the default TCG template into a transient
/// context file (DDR-005 decision 2). It is never persisted.
///
/// Assumes the endorsement hierarchy has an empty authorization, as on the
/// bench. A device whose endorsement auth is set needs it passed here and in
/// the policy session of activation; that is an assumption to record for the
/// release image, not something this function detects.
fn create_ek(work: &Path) -> R<String> {
    let ctx = work.join("ek.ctx").to_string_lossy().to_string();
    let pubf = work.join("ek.pub").to_string_lossy().to_string();
    run(&["tpm2_createek", "-c", &ctx, "-G", "rsa", "-u", &pubf])?;
    let _ = run(&["tpm2_flushcontext", "-t"]);
    Ok(ctx)
}

/// Create the ECDSA P-256 attestation key (AK) under the EK, in the
/// endorsement hierarchy (DDR-005 decision 3), and persist it at `AK_HANDLE`.
///
/// The caller must have checked that `AK_HANDLE` is free.
///
/// In the endorsement hierarchy the quote carries `resetCount`,
/// `restartCount` and `firmwareVersion` in the clear; under an owner parent
/// the TPM obfuscates them (DDR-004 boundary D).
///
/// Restricted signing key (DDR-004 decision 7): the TPM will sign with it only
/// structures it produced itself (a quote) or data it hashed and ticketed, and
/// refuses external data that imitates a TPM structure. That refusal is what
/// makes a quote evidence of measured state rather than of whatever the
/// prover assembled. `tpm2_createak` sets the attributes of DDR-004 decision 7
/// and the null symmetric scheme itself (DDR-005 Verification); the registrar
/// checks the result against the DDR-004 decision 4 rule, so a tool version
/// that created something else is caught there, not trusted here.
///
/// The key is deliberately NOT sealed to a PCR policy.
///
/// Sealing would mean a device in an un-enrolled state could not attest at
/// all. The verifier would then observe silence rather than a signed
/// attestation of a state it does not recognise, and `verifier-rats`
/// distinguishes `UnrecognizedState` (device honestly attested something not in
/// the golden set) from `SignatureFail` (forgery) precisely so the consumer can
/// quarantine in one case and alarm in the other. A PCR-sealed key collapses
/// that distinction, and also makes a compromised device indistinguishable from
/// one that is merely powered off. A quote keeps the distinction: it signs the
/// current PCRs whatever they are.
pub fn create_ak(work: &Path) -> R<()> {
    let pubf = work.join("ak.pub");
    let privf = work.join("ak.priv");
    let ctx = work.join("ak.ctx");
    let (pubf, privf, ctx) = (
        pubf.to_string_lossy().to_string(),
        privf.to_string_lossy().to_string(),
        ctx.to_string_lossy().to_string(),
    );
    let ek = create_ek(work)?;
    // Loading a child of the EK needs the EK's policy (PolicySecret on the
    // endorsement hierarchy); tpm2_createak runs that session itself.
    run(&[
        "tpm2_createak", "-C", &ek, "-c", &ctx, "-G", "ecc", "-g", "sha256", "-s", "ecdsa",
        "-u", &pubf, "-r", &privf,
    ])?;
    let _ = run(&["tpm2_flushcontext", "-t"]);
    // Persisting the key means the quote path needs no transient load per
    // cycle: one TPM object, reused for the life of the device.
    run(&["tpm2_evictcontrol", "-C", "o", "-c", &ctx, AK_HANDLE])?;
    let _ = run(&["tpm2_flushcontext", "-t"]);
    Ok(())
}

/// Write the persisted AK's public area as `TPM2B_PUBLIC`, the form the
/// verifier's `AkKey::from_tpm2b_public` accepts. Not a PEM on purpose: the
/// verifier derives "this is an AK" from the attributes in this structure, and
/// a PEM would drop them.
pub fn read_ak_public(out: &Path) -> R<()> {
    let out = out.to_string_lossy().to_string();
    run(&["tpm2_readpublic", "-c", AK_HANDLE, "-o", &out])?;
    Ok(())
}

/// Compare two `TPM2B_PUBLIC` areas by TPM name. `recorded` is the public area
/// written at provisioning, `at_handle` the one the TPM reports now.
///
/// Both are parsed (an ECC key with a sha256 name), and the names are computed
/// here rather than taken from tool output.
pub fn same_ak(recorded: &[u8], at_handle: &[u8]) -> R<()> {
    use attest_envelope::tpm::EccPublic;
    let r = EccPublic::parse_tpm2b(recorded)
        .and_then(|p| p.name())
        .map_err(|e| format!("recorded AK public area unusable ({e}); \
                  it was not written by this agent version, re-provision deliberately"))?;
    let h = EccPublic::parse_tpm2b(at_handle)
        .and_then(|p| p.name())
        .map_err(|e| format!("object at {AK_HANDLE} is not an ECC AK ({e})"))?;
    if r != h {
        let hex = |n: &[u8]| n.iter().map(|b| format!("{b:02x}")).collect::<String>();
        return Err(format!(
            "object at {AK_HANDLE} has name {}, the recorded AK has {}; refusing to use a key \
             that is not the one provisioned (DDR-005 decision 4)",
            hex(&h),
            hex(&r)
        ));
    }
    Ok(())
}

/// Before any use of the AK: the object at `AK_HANDLE` must be the AK whose
/// public area was recorded at provisioning (`recorded`, `keys/ak.pub`).
pub fn verify_ak(recorded: &Path, work: &Path) -> R<()> {
    if !handle_exists(AK_HANDLE)? {
        return Err(format!("no object at {AK_HANDLE}; the recorded AK is not in this TPM"));
    }
    let rec = std::fs::read(recorded)
        .map_err(|e| format!("read {}: {e}", recorded.display()))?;
    let cur_path = work.join("ak.handle.pub");
    read_ak_public(&cur_path)?;
    let cur = std::fs::read(&cur_path)
        .map_err(|e| format!("read {}: {e}", cur_path.display()))?;
    same_ak(&rec, &cur)
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

/// Quote the selected PCRs with the AK, committing to the canonical message.
///
/// `qualifyingData = SHA-256(msg)` (`attest_envelope::tpm::qualifying_data`),
/// so the TPM-signed `TPMS_ATTEST` binds the message and, through it, the
/// counter and the evidence digest. `spec` must be the same string the PCRs
/// were read with; the verifier refuses a quote whose selection or digest
/// differs from the message. `-f plain` keeps the signature format the v1
/// path used (the verifier accepts DER or r||s).
pub fn quote(msg: &[u8], spec: &str, attest: &Path, sig: &Path) -> R<()> {
    let qd = attest_envelope::tpm::qualifying_data(msg)?;
    let hex: String = qd.iter().map(|b| format!("{b:02x}")).collect();
    let (a, s) = (attest.to_string_lossy().to_string(), sig.to_string_lossy().to_string());
    run(&[
        "tpm2_quote", "-c", AK_HANDLE, "-l", spec, "-q", &hex,
        "-m", &a, "-s", &s, "-g", "sha256", "-f", "plain",
    ])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{listing_has, parse_pcr_spec, same_ak};

    fn fixture(name: &str) -> Vec<u8> {
        let p = format!(
            "{}/../attest-appraise/tests/fixtures/swtpm/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
    }

    #[test]
    fn listing_match_is_exact_per_line() {
        let l = "- 0x81010001\n- 0x81010100\n";
        assert!(listing_has(l, "0x81010100"));
        assert!(listing_has(l, "0X81010100"));
        assert!(!listing_has(l, "0x8101010"));
        assert!(!listing_has(l, "0x81010003"));
        assert!(!listing_has("", "0x81010100"));
        // a handle inside other text is not a listing entry
        assert!(!listing_has("error near 0x81010100\n", "0x81010100"));
    }

    #[test]
    fn same_public_area_is_the_same_ak() {
        let ak = fixture("ak.pub");
        assert!(same_ak(&ak, &ak).is_ok());
    }

    #[test]
    fn another_key_at_the_handle_is_refused() {
        let err = same_ak(&fixture("ak.pub"), &fixture("not-ak.pub")).unwrap_err();
        assert!(err.contains("refusing"), "{err}");
    }

    #[test]
    fn one_changed_byte_changes_the_name() {
        let ak = fixture("ak.pub");
        let mut other = ak.clone();
        let last = other.len() - 1; // inside unique.y
        other[last] ^= 1;
        assert!(same_ak(&ak, &other).is_err());
    }

    #[test]
    fn a_pem_recorded_by_an_older_agent_is_refused() {
        let pem = b"-----BEGIN PUBLIC KEY-----\n".to_vec();
        let err = same_ak(&pem, &fixture("ak.pub")).unwrap_err();
        assert!(err.contains("re-provision"), "{err}");
    }

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
