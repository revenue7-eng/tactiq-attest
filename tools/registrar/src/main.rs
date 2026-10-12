//! tactiq-registrar: the registrar side of AK registration (DDR-005).
//!
//!   begin     check the EK chain and the AK, draw a secret, make the blob
//!   complete  compare the device's answer with the secret, write the record
//!   verify    re-check a record (decision 7) and emit the AK for the trust store
//!
//! `begin` and `complete` share a state directory. The secret waits there,
//! 0600, until `complete` compares it and deletes it. The protocol does not
//! rely on the secret staying confidential after the TPM releases it (DDR-005,
//! "The secret on the console"); the file mode is ordinary hygiene.
//!
//! A record from this tool is unsigned: it is signed afterwards as a file by
//! the `Registration Signer` leaf (decision 6), detached, and `verify --sig`
//! checks that signature (`signature.rs`). A signature is a separate file,
//! never a field. An unsigned record is internal and never presented as L3.
//!
//! Record formats. `tactiq-ak-registration/2` (written by this tool) carries
//! the CRLs of both CAs of the EK chain, checked at the chain check time
//! (`crl.rs`), and has no `signed` field. `tactiq-ak-registration/1` (the
//! records of v2.1.0-rc13) had `signed: false`, which read as the opposite of
//! a record with a detached signature, and `revocation_checked: false`; it is
//! still verified, by its own rules, and is no longer written.

mod chain;
mod crl;
mod makecred;
mod signature;

use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use attest_appraise::AkKey;
use attest_envelope::tpm::EccPublic;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const RECORD_FORMAT: &str = "tactiq-ak-registration/2";
const RECORD_FORMAT_V1: &str = "tactiq-ak-registration/1";
const PENDING_FORMAT: &str = "tactiq-ak-registration-pending/1";
const EK_NV_INDEX: &str = "0x01C00002";
const DEVICE_ID_MAX: usize = attest_envelope::DEVICE_ID_LEN;

/// The registration record (DDR-005 decision 6). Binary fields are lowercase
/// hex. It is signed later as a file, over its exact bytes, so nothing here
/// depends on JSON canonicalisation.
#[derive(Serialize, Deserialize)]
struct Record {
    format: String,
    device_id: String,
    registrar: String,
    /// When the EK chain was checked (at `begin`), RFC 3339 UTC and Unix seconds.
    chain_checked_utc: String,
    chain_checked_unix: u64,
    /// When the answer matched (at `complete`).
    registered_utc: String,
    ek_nv_index: String,
    ek_certificate: String,
    intermediate_certificate: String,
    root_sha256: String,
    /// The chain check this tool performs; see `chain.rs`.
    chain_check: String,
    revocation_checked: bool,
    /// Format 2: the revocation check (`crl.rs`) and the CRLs it used, DER as
    /// hex, with their own thisUpdate and nextUpdate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revocation_check: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ek_crl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ek_crl_this_update_utc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ek_crl_next_update_utc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    intermediate_crl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    intermediate_crl_this_update_utc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    intermediate_crl_next_update_utc: Option<String>,
    ak_public: String,
    ak_name: String,
    /// tpm2-tools credential file bytes.
    credential_blob: String,
    secret_sha256: String,
    /// Format 1 only, always false there; not written by this tool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signed: Option<bool>,
}

#[derive(Serialize, Deserialize)]
struct Pending {
    format: String,
    device_id: String,
    registrar: String,
    chain_checked_unix: u64,
    ek_certificate: String,
    intermediate_certificate: String,
    root_sha256: String,
    ek_crl: String,
    ek_crl_this_update_unix: u64,
    ek_crl_next_update_unix: u64,
    intermediate_crl: String,
    intermediate_crl_this_update_unix: u64,
    intermediate_crl_next_update_unix: u64,
    ak_public: String,
    ak_name: String,
    credential_blob: String,
    secret: String,
}

const CHAIN_CHECK: &str = "EK <- intermediate <- pinned root; sha256WithRSAEncryption; \
     issuer/subject byte match; signatures; validity at chain_checked_utc; \
     CA flags and keyCertSign on both CAs; EK not a CA, EKU tcg-kp-EKCertificate; \
     unknown critical extensions refused";

const REVOCATION_CHECK: &str = "EK certificate against the CRL of its issuing CA, issuing CA \
     against the CRL of the root; sha256WithRSAEncryption by the issuing key with cRLSign; \
     CRL issuer byte match; thisUpdate <= chain_checked_utc <= nextUpdate; \
     no critical CRL extension; serial not listed";

type R<T> = Result<T, String>;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = match args.first().map(String::as_str) {
        Some("begin") => cmd_begin(&opts(&args[1..])),
        Some("complete") => cmd_complete(&opts(&args[1..])),
        Some("verify") => cmd_verify(&opts(&args[1..])),
        _ => {
            eprintln!(
                "tactiq-registrar <command> [--option value ...]\n\n\
                 begin     --state DIR --device-id ID --ak-public FILE --ek-cert FILE\n\
                 \x20         --intermediate FILE --root FILE --registrar NAME\n\
                 \x20         --ek-crl FILE --intermediate-crl FILE\n\
                 complete  --state DIR --answer FILE\n\
                 verify    --record FILE --root FILE [--emit-ak FILE]\n\
                 \x20         [--sig FILE.p7s --release-root FILE]"
            );
            std::process::exit(2);
        }
    };
    if let Err(e) = r {
        eprintln!("tactiq-registrar: {e}");
        std::process::exit(1);
    }
}

struct Opts(Vec<(String, String)>);

fn opts(a: &[String]) -> Opts {
    let mut v = Vec::new();
    let mut i = 0;
    while i < a.len() {
        let k = a[i].trim_start_matches("--").to_string();
        let val = a.get(i + 1).cloned().unwrap_or_default();
        v.push((k, val));
        i += 2;
    }
    Opts(v)
}

impl Opts {
    fn get(&self, k: &str) -> R<&str> {
        self.0
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty() && !v.starts_with("--"))
            .ok_or_else(|| format!("missing --{k}"))
    }
    fn opt(&self, k: &str) -> Option<&str> {
        self.get(k).ok()
    }
}

fn read(p: &str) -> R<Vec<u8>> {
    fs::read(p).map_err(|e| format!("read {p}: {e}"))
}

fn now() -> Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock after 1970")
}

/// RFC 3339 UTC from Unix seconds (proleptic Gregorian, civil-from-days).
fn utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

fn validate_id(id: &str) -> R<()> {
    if id.is_empty() || id.len() > DEVICE_ID_MAX || !id.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!("device id {id:?}: 1..={DEVICE_ID_MAX} printable ASCII bytes, no spaces"));
    }
    Ok(())
}

/// The AK must qualify under DDR-004 decision 4 (the verifier's own rule) and
/// have a computable name. Returns the name.
fn check_ak(ak_public: &[u8]) -> R<[u8; 34]> {
    AkKey::from_tpm2b_public(ak_public).map_err(|e| format!("AK public area refused by the AK rule: {e:?}"))?;
    EccPublic::parse_tpm2b(ak_public).and_then(|p| p.name())
}

fn write_new(p: &Path, bytes: &[u8], mode: u32) -> R<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(p)
        .map_err(|e| format!("create {}: {e}", p.display()))?;
    f.write_all(bytes).and_then(|_| f.sync_all()).map_err(|e| format!("write {}: {e}", p.display()))
}

fn print_hex_lines(b: &[u8]) {
    for chunk in hex::encode(b).as_bytes().chunks(64) {
        println!("{}", std::str::from_utf8(chunk).unwrap());
    }
}

fn cmd_begin(o: &Opts) -> R<()> {
    let state = PathBuf::from(o.get("state")?);
    let device_id = o.get("device-id")?.to_string();
    validate_id(&device_id)?;
    let registrar = o.get("registrar")?.to_string();
    let ek_der = read(o.get("ek-cert")?)?;
    let int_der = read(o.get("intermediate")?)?;
    let root_der = read(o.get("root")?)?;
    let ak_public = read(o.get("ak-public")?)?;
    let ek_crl = read(o.get("ek-crl")?)?;
    let int_crl = read(o.get("intermediate-crl")?)?;

    let at = now();
    let chain = chain::verify(&ek_der, &int_der, &root_der, at)?;
    let (ec, ic) = crl::check_chain(&ek_der, &int_der, &root_der, &ek_crl, &int_crl, at)?;
    let name = check_ak(&ak_public)?;

    let mut secret = [0u8; makecred::SECRET_LEN];
    OsRng.fill_bytes(&mut secret);
    let blob = makecred::make_credential(&chain.ek_public, &name, &secret, &mut OsRng)?;

    fs::DirBuilder::new()
        .mode(0o700)
        .create(&state)
        .map_err(|e| format!("create {} (must not exist yet): {e}", state.display()))?;
    let pending = Pending {
        format: PENDING_FORMAT.into(),
        device_id: device_id.clone(),
        registrar,
        chain_checked_unix: at.as_secs(),
        ek_certificate: hex::encode(&ek_der),
        intermediate_certificate: hex::encode(&int_der),
        root_sha256: hex::encode(chain.root_sha256),
        ek_crl: hex::encode(&ek_crl),
        ek_crl_this_update_unix: ec.this_update_unix,
        ek_crl_next_update_unix: ec.next_update_unix,
        intermediate_crl: hex::encode(&int_crl),
        intermediate_crl_this_update_unix: ic.this_update_unix,
        intermediate_crl_next_update_unix: ic.next_update_unix,
        ak_public: hex::encode(&ak_public),
        ak_name: hex::encode(name),
        credential_blob: hex::encode(&blob),
        secret: hex::encode(secret),
    };
    let json = serde_json::to_vec_pretty(&pending).map_err(|e| e.to_string())?;
    write_new(&state.join("pending.json"), &json, 0o600)?;
    write_new(&state.join("cred.blob"), &blob, 0o644)?;

    println!("device      {device_id}");
    println!("root sha256 {}", hex::encode(chain.root_sha256));
    println!("revocation  EK not listed (CRL {} to {}), intermediate not listed (CRL {} to {})",
        utc(ec.this_update_unix), utc(ec.next_update_unix), utc(ic.this_update_unix), utc(ic.next_update_unix));
    println!("ak name     {}", hex::encode(name));
    println!("blob        {} ({} bytes)", state.join("cred.blob").display(), blob.len());
    println!("blob sha256 {}", hex::encode(Sha256::digest(&blob)));
    println!("blob hex:");
    print_hex_lines(&blob);
    Ok(())
}

/// The device's answer: the released secret as hex. Whitespace is ignored, and
/// so is a leading `certinfodata:` as printed by `tpm2_activatecredential`.
fn parse_answer(text: &str) -> R<[u8; makecred::SECRET_LEN]> {
    let t: String = text.split_whitespace().collect();
    let t = t.strip_prefix("certinfodata:").unwrap_or(&t);
    let b = hex::decode(t).map_err(|e| format!("answer is not hex: {e}"))?;
    b.try_into().map_err(|b: Vec<u8>| format!("answer is {} bytes, want {}", b.len(), makecred::SECRET_LEN))
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn cmd_complete(o: &Opts) -> R<()> {
    let state = PathBuf::from(o.get("state")?);
    let pending_path = state.join("pending.json");
    let p: Pending = serde_json::from_slice(&read(pending_path.to_str().unwrap())?)
        .map_err(|e| format!("{}: {e}", pending_path.display()))?;
    if p.format != PENDING_FORMAT {
        return Err(format!("{}: format {}", pending_path.display(), p.format));
    }
    let answer_text = String::from_utf8(read(o.get("answer")?)?).map_err(|_| "answer is not text".to_string())?;
    let answer = parse_answer(&answer_text)?;
    let secret = hex::decode(&p.secret).map_err(|e| e.to_string())?;

    if !ct_eq(&answer, &secret) {
        // The pending state is kept: a mistyped answer is not a failed device.
        // A device that cannot open the blob will never produce the match.
        return Err("the answer does not match the secret; registration NOT made".into());
    }

    let rec = Record {
        format: RECORD_FORMAT.into(),
        device_id: p.device_id,
        registrar: p.registrar,
        chain_checked_utc: utc(p.chain_checked_unix),
        chain_checked_unix: p.chain_checked_unix,
        registered_utc: utc(now().as_secs()),
        ek_nv_index: EK_NV_INDEX.into(),
        ek_certificate: p.ek_certificate,
        intermediate_certificate: p.intermediate_certificate,
        root_sha256: p.root_sha256,
        chain_check: CHAIN_CHECK.into(),
        revocation_checked: true,
        revocation_check: Some(REVOCATION_CHECK.into()),
        ek_crl: Some(p.ek_crl),
        ek_crl_this_update_utc: Some(utc(p.ek_crl_this_update_unix)),
        ek_crl_next_update_utc: Some(utc(p.ek_crl_next_update_unix)),
        intermediate_crl: Some(p.intermediate_crl),
        intermediate_crl_this_update_utc: Some(utc(p.intermediate_crl_this_update_unix)),
        intermediate_crl_next_update_utc: Some(utc(p.intermediate_crl_next_update_unix)),
        ak_public: p.ak_public,
        ak_name: p.ak_name,
        credential_blob: p.credential_blob,
        secret_sha256: hex::encode(Sha256::digest(&secret)),
        signed: None,
    };
    let mut json = serde_json::to_vec_pretty(&rec).map_err(|e| e.to_string())?;
    json.push(b'\n');
    let out = state.join("record.json");
    write_new(&out, &json, 0o644)?;
    fs::remove_file(&pending_path).map_err(|e| format!("remove {}: {e}", pending_path.display()))?;

    println!("registered  {}", rec.device_id);
    println!("record      {}", out.display());
    println!("record sha256 {}", hex::encode(Sha256::digest(&json)));
    println!("unsigned: internal only, not L3 (DDR-005 decision 6)");
    Ok(())
}

fn unhex(field: &str, v: &str) -> R<Vec<u8>> {
    hex::decode(v).map_err(|e| format!("record field {field}: {e}"))
}

fn cmd_verify(o: &Opts) -> R<()> {
    let record_bytes = read(o.get("record")?)?;
    let rec: Record = serde_json::from_slice(&record_bytes).map_err(|e| format!("record: {e}"))?;
    let v2 = match rec.format.as_str() {
        RECORD_FORMAT => true,
        RECORD_FORMAT_V1 => false,
        f => return Err(format!("record format {f}")),
    };
    if v2 {
        if rec.signed.is_some() {
            return Err("format 2 record carries a `signed` field; a signature is a separate file (--sig)".into());
        }
        if !rec.revocation_checked {
            return Err("format 2 record without a revocation check".into());
        }
    } else {
        if rec.signed != Some(false) {
            return Err("format 1 record: field `signed` must be false; a signature is a separate file (--sig)".into());
        }
        if rec.revocation_checked {
            return Err("format 1 record claims a revocation check format 1 never made".into());
        }
    }
    validate_id(&rec.device_id)?;

    let root_der = read(o.get("root")?)?;
    let root_sha = hex::encode(Sha256::digest(&root_der));
    if root_sha != rec.root_sha256 {
        return Err(format!("root: sha256 {root_sha}, record names {}", rec.root_sha256));
    }
    let ek_der = unhex("ek_certificate", &rec.ek_certificate)?;
    let int_der = unhex("intermediate_certificate", &rec.intermediate_certificate)?;
    let at = Duration::from_secs(rec.chain_checked_unix);
    chain::verify(&ek_der, &int_der, &root_der, at)?;
    if v2 {
        let need = |f: &str, v: &Option<String>| v.clone().ok_or_else(|| format!("format 2 record without {f}"));
        let ek_crl = unhex("ek_crl", &need("ek_crl", &rec.ek_crl)?)?;
        let int_crl = unhex("intermediate_crl", &need("intermediate_crl", &rec.intermediate_crl)?)?;
        let (ec, ic) = crl::check_chain(&ek_der, &int_der, &root_der, &ek_crl, &int_crl, at)?;
        for (f, got, want) in [
            ("ek_crl_this_update_utc", &rec.ek_crl_this_update_utc, ec.this_update_unix),
            ("ek_crl_next_update_utc", &rec.ek_crl_next_update_utc, ec.next_update_unix),
            ("intermediate_crl_this_update_utc", &rec.intermediate_crl_this_update_utc, ic.this_update_unix),
            ("intermediate_crl_next_update_utc", &rec.intermediate_crl_next_update_utc, ic.next_update_unix),
        ] {
            if got.as_deref() != Some(utc(want).as_str()) {
                return Err(format!("record field {f} {:?} does not match the CRL ({})", got, utc(want)));
            }
        }
    }

    let ak_public = unhex("ak_public", &rec.ak_public)?;
    let name = check_ak(&ak_public)?;
    if hex::encode(name) != rec.ak_name {
        return Err(format!("ak_name {} does not match the AK public area ({})", rec.ak_name, hex::encode(name)));
    }
    makecred::parse_file(&unhex("credential_blob", &rec.credential_blob)?)?;
    if unhex("secret_sha256", &rec.secret_sha256)?.len() != 32 {
        return Err("secret_sha256 is not 32 bytes".into());
    }

    // The signature is judged last, after the record itself holds, and at the
    // current time: a record stops verifying when a certificate above it
    // expires, the Signing CA included.
    let signer = match (o.opt("sig"), o.opt("release-root")) {
        (Some(p7s), Some(root)) => {
            let root_der = signature::cert_der(&read(root)?, "release root")?;
            Some(signature::verify(&record_bytes, &read(p7s)?, &root_der, now())?)
        }
        (None, None) => None,
        _ => return Err("--sig and --release-root go together".into()),
    };

    if v2 {
        println!("record ok   {} (format 2: chain and CRLs at {}, AK rule, AK name, blob layout)", rec.device_id, rec.chain_checked_utc);
        println!("not checked: the blob contents (activate on the device), who registered");
    } else {
        println!("record ok   {} (format 1: chain at {}, AK rule, AK name, blob layout)", rec.device_id, rec.chain_checked_utc);
        println!("not checked: the blob contents (activate on the device), revocation, who registered");
    }
    match signer {
        Some(s) => {
            println!("signed      by {} (serial {})", s.leaf_subject, s.leaf_serial);
            println!("            Signing CA {}; release root sha256 {}", s.signing_ca_subject, s.root_sha256);
            println!("            signer EKU is the registration purpose; certificates valid now");
        }
        None => println!("unsigned: internal only, not L3"),
    }
    if let Some(p) = o.opt("emit-ak") {
        write_new(Path::new(p), &ak_public, 0o644)?;
        println!("AK public area written to {p}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_matches_known_instants() {
        assert_eq!(utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(utc(1_790_294_400), "2026-09-25T00:00:00Z");
    }

    #[test]
    fn answer_accepts_tool_output_and_plain_hex() {
        let s = "ab".repeat(32);
        assert_eq!(parse_answer(&s).unwrap(), [0xab; 32]);
        assert_eq!(parse_answer(&format!("certinfodata:{s}\n")).unwrap(), [0xab; 32]);
        assert_eq!(parse_answer(&format!("{}\n {}", &s[..32], &s[32..])).unwrap(), [0xab; 32]);
        assert!(parse_answer(&"ab".repeat(31)).is_err());
        assert!(parse_answer("zz").is_err());
    }

    #[test]
    fn constant_time_compare() {
        assert!(ct_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!ct_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!ct_eq(&[1, 2], &[1, 2, 3]));
    }
}
