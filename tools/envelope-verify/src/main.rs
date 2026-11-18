//! tactiq-envelope-verify: check one attestation envelope of tactiq-agent on
//! the verifier's machine, offline.
//!
//!   check STEM   check `STEM.msg`, `STEM.attest`, `STEM.sig` and, if present,
//!                the evidence bundle `STEM.tag`
//!
//! What `check` is given, and where it should come from:
//!
//!   --ak FILE        the AK as `TPM2B_PUBLIC`: `tactiq-registrar verify
//!                    --emit-ak` from the device's registration record. Taken
//!                    from the device itself it proves only that the envelope
//!                    and the file came from the same key.
//!   --device ID      the device the envelope is expected from.
//!   --pcr-ref FILE   the reference of the build the verifier accepts
//!                    (`tactiq-pcr-reference/1` or `/2`, mk-pcr-reference.py);
//!                    `--slot` when PCR 1 differs per slot. The PCRs it lists
//!                    are the selection the envelope must have quoted.
//!
//! The check is `attest_appraise::authenticate_envelope` and
//! `attest_appraise::appraise`, stateless. It answers: was this envelope
//! signed through a TPM quote by this device's AK, does the quote commit to
//! this message, is the bundle the one that was signed over, and was the
//! measured state the reference's at the moment of signing. It does not
//! answer whether this is the device's latest envelope: that needs the
//! highest counter already accepted from the device, which a stateless check
//! does not have.
//!
//! Exit status: 0 accepted, 1 refused.

use std::fs;
use std::path::Path;
use std::process::ExitCode;

use attest_appraise::{appraise, authenticate_envelope, AkKey, Binding, PcrSelection, ReferenceSet, TrustEntry};
use attest_envelope::{encode_pcr_selection, DEVICE_ID_LEN};
use sha2::{Digest, Sha256};

const SHA256: u16 = 0x000B;

const USAGE: &str =
    "usage:\n  tactiq-envelope-verify check STEM --ak FILE --device ID --pcr-ref FILE [--slot A|B]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = match args.first().map(String::as_str) {
        Some("check") => check(&args[1..]),
        _ => Err(USAGE.into()),
    };
    match r {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("tactiq-envelope-verify: {e}");
            println!("VERDICT     REFUSED");
            ExitCode::from(1)
        }
    }
}

struct Opts<'a> {
    stem: &'a str,
    ak: &'a str,
    device: &'a str,
    pcr_ref: &'a str,
    slot: Option<&'a str>,
}

fn opts(a: &[String]) -> Result<Opts<'_>, String> {
    let stem = a.first().filter(|s| !s.starts_with("--")).ok_or(USAGE)?;
    let (mut ak, mut device, mut pcr_ref, mut slot) = (None, None, None, None);
    let mut i = 1;
    while i < a.len() {
        let val = a.get(i + 1).map(String::as_str).ok_or_else(|| format!("{} needs a value", a[i]))?;
        match a[i].as_str() {
            "--ak" => ak = Some(val),
            "--device" => device = Some(val),
            "--pcr-ref" => pcr_ref = Some(val),
            "--slot" => slot = Some(val),
            other => return Err(format!("unknown option {other}\n{USAGE}")),
        }
        i += 2;
    }
    Ok(Opts {
        stem,
        ak: ak.ok_or("--ak is required")?,
        device: device.ok_or("--device is required")?,
        pcr_ref: pcr_ref.ok_or("--pcr-ref is required")?,
        slot,
    })
}

fn read(path: &str) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("read {path}: {e}"))
}

fn check(a: &[String]) -> Result<u8, String> {
    let o = opts(a)?;
    let msg = read(&format!("{}.msg", o.stem))?;
    let attest = read(&format!("{}.attest", o.stem))?;
    let sig = read(&format!("{}.sig", o.stem))?;
    let tag_path = format!("{}.tag", o.stem);
    let bundle = if Path::new(&tag_path).exists() { read(&tag_path)? } else { Vec::new() };

    let ak = AkKey::from_tpm2b_public(&read(o.ak)?).map_err(|e| format!("{}: {e}", o.ak))?;
    let ref_text = fs::read_to_string(o.pcr_ref).map_err(|e| format!("read {}: {e}", o.pcr_ref))?;
    let (selection, composite, pcrs, ref_note) = reference(&ref_text, o.slot)?;
    let want = device_id(o.device)?;

    println!("envelope    {} (.msg {} bytes, .attest {}, .sig {}, bundle {})", o.stem, msg.len(), attest.len(), sig.len(), bundle.len());
    println!("device      {}", o.device);
    println!("ak          name {}", hex(ak.name()));

    let auth = authenticate_envelope(&msg, Some(&attest), &sig, &bundle, |id| {
        (id == &want).then(|| TrustEntry::Ak(ak.clone()))
    });
    let auth = match auth {
        Ok(a) => a,
        Err(e) => {
            println!("refused at  signature, quote and bundle checks: {}", e.detail);
            println!("VERDICT     REJECT {:?}", attest_appraise::Reason::from(e.reason));
            return Ok(1);
        }
    };
    let binding = match auth.binding() {
        Binding::TpmQuote => "TPM quote under the AK, committing to the message",
        _ => "not a TPM quote",
    };
    println!("signed      {binding}; bundle bound to the signed evidence_hash");
    println!("counter     {} (as signed; whether it is the newest is not checked here)", auth.counter());

    let refs = ReferenceSet::new(PcrSelection::from_canonical(&selection), vec![composite]);
    let v = appraise(&auth, &refs);
    println!("build       PCR {pcrs} against {}{ref_note}", o.pcr_ref);
    println!("not shown   that this is the device's latest envelope: that needs the highest counter already accepted from it");
    if v.is_accept() {
        println!("VERDICT     ACCEPT");
        Ok(0)
    } else {
        println!("VERDICT     REJECT {:?}", v.reason);
        Ok(1)
    }
}

/// The selection and composite a device booted into the referenced build
/// quotes: every PCR the reference lists, in index order, SHA-256 over their
/// values.
fn reference(text: &str, slot: Option<&str>) -> Result<([u8; 5], [u8; 32], String, String), String> {
    let doc: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("pcr reference: {e}"))?;
    let format = doc["format"].as_str().unwrap_or("");
    if format != "tactiq-pcr-reference/1" && format != "tactiq-pcr-reference/2" {
        return Err(format!("pcr reference: format {format:?}, want tactiq-pcr-reference/1 or /2"));
    }
    if doc["bank"].as_str() != Some("sha256") {
        return Err("pcr reference: bank is not sha256".into());
    }
    let map = doc["pcr"].as_object().ok_or("pcr reference: no pcr map")?;
    let mut idx: Vec<u32> = Vec::new();
    for k in map.keys() {
        let i: u32 = k.parse().map_err(|_| format!("pcr reference: PCR index {k:?} is not a number"))?;
        if i > 23 {
            return Err(format!("pcr reference: PCR {i} is out of range"));
        }
        idx.push(i);
    }
    idx.sort_unstable();
    if idx.is_empty() {
        return Err("pcr reference: no PCRs".into());
    }
    let mut bitmap = [0u8; 3];
    let mut h = Sha256::new();
    let mut per_slot = false;
    for &i in &idx {
        bitmap[(i / 8) as usize] |= 1 << (i % 8);
        let v = &map[&i.to_string()];
        let hexval = match (v, slot) {
            (serde_json::Value::String(s), _) => s.as_str(),
            (serde_json::Value::Object(m), Some(s)) => {
                per_slot = true;
                m.get(s).and_then(|x| x.as_str()).ok_or_else(|| format!("pcr reference: PCR {i} has no value for slot {s}"))?
            }
            (serde_json::Value::Object(_), None) => return Err(format!("pcr reference: PCR {i} differs per slot; give --slot")),
            _ => return Err(format!("pcr reference: PCR {i} is not a value")),
        };
        let b = unhex(hexval).map_err(|e| format!("pcr reference: PCR {i}: {e}"))?;
        if b.len() != 32 {
            return Err(format!("pcr reference: PCR {i} is {} bytes, want 32", b.len()));
        }
        h.update(&b);
    }
    let list = idx.iter().map(u32::to_string).collect::<Vec<_>>().join(", ");
    let note = match (per_slot, slot) {
        (true, Some(s)) => format!(", slot {s}"),
        (false, Some(s)) => format!(" (same for every slot; --slot {s} not needed)"),
        _ => String::new(),
    };
    Ok((encode_pcr_selection(SHA256, bitmap), h.finalize().into(), list, note))
}

fn device_id(s: &str) -> Result<[u8; DEVICE_ID_LEN], String> {
    if s.is_empty() || s.len() > DEVICE_ID_LEN || !s.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!("--device {s:?}: 1..={DEVICE_ID_LEN} printable ASCII characters"));
    }
    let mut d = [0u8; DEVICE_ID_LEN];
    d[..s.len()].copy_from_slice(s.as_bytes());
    Ok(d)
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("not an even number of hex digits".into());
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string())).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn doc(pcrs: &[u32]) -> String {
        let body: Vec<String> = pcrs.iter().map(|i| format!("\"{i}\":\"{ZERO}\"")).collect();
        format!(r#"{{"format":"tactiq-pcr-reference/2","bank":"sha256","pcr":{{{}}}}}"#, body.join(","))
    }

    #[test]
    fn selection_and_composite_follow_the_listed_pcrs_in_index_order() {
        let (sel, c, list, _) = reference(&doc(&[9, 0, 1, 2, 3, 4, 5, 6, 7, 8]), None).unwrap();
        assert_eq!(sel, encode_pcr_selection(SHA256, [0xFF, 0x03, 0x00]));
        assert_eq!(c, <[u8; 32]>::from(Sha256::digest([0u8; 320])));
        assert_eq!(list, "0, 1, 2, 3, 4, 5, 6, 7, 8, 9");
    }

    #[test]
    fn a_per_slot_pcr_needs_the_slot() {
        let one = "11".repeat(32);
        let d = format!(r#"{{"format":"tactiq-pcr-reference/2","bank":"sha256","pcr":{{"0":"{ZERO}","1":{{"A":"{ZERO}","B":"{one}"}}}}}}"#);
        assert!(reference(&d, None).is_err());
        assert!(reference(&d, Some("C")).is_err());
        let (_, a, _, _) = reference(&d, Some("A")).unwrap();
        let (_, b, _, _) = reference(&d, Some("B")).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn another_format_bank_or_index_is_refused() {
        let d = doc(&[0, 1]);
        assert!(reference(&d.replace("reference/2", "reference/9"), None).is_err());
        assert!(reference(&d.replace("\"sha256\"", "\"sha1\""), None).is_err());
        assert!(reference(&d.replace("\"1\":", "\"24\":"), None).is_err());
        assert!(reference(&d.replace("\"1\":", "\"x\":"), None).is_err());
    }
}
