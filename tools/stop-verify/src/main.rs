//! tactiq-stop-verify: is the agent on this device stopped, now, and who says
//! so. Runs on the verifier's machine, offline.
//!
//!   nonce   print a fresh 32-byte challenge, hex, from the OS
//!   check   check a receipt from `tactiq-stop status <nonce>` (or a 403 body)
//!
//! The round trip on an air-gapped site: `nonce` here, the hex carried to the
//! device, `tactiq-stop status <hex> > receipt` there, the receipt carried
//! back, `check` here. The nonce is the verifier's: a receipt that answers it
//! was made after it was chosen.
//!
//! What `check` is given, and where it should come from:
//!
//!   --ak FILE        the AK as `TPM2B_PUBLIC`: `tactiq-registrar verify
//!                    --emit-ak` from the device's registration record. Taken
//!                    from the device itself it proves only that the receipt
//!                    and the file came from the same key.
//!   --device ID      the device asked.
//!   --pcr-ref FILE   the reference of the build the verifier accepts
//!                    (`tactiq-pcr-reference/1` or `/2`, mk-pcr-reference.py);
//!                    `--slot` when PCR 1 differs per slot.
//!   --nonce HEX      the challenge sent; `--no-nonce` for a 403 body, which
//!                    proves what the service said but not when.
//!
//! Exit status: 0 verified and stopped, 2 verified and running, 1 refused.

use std::fs;
use std::process::ExitCode;

use attest_appraise::{verify_stop_receipt, AkKey, StopBasis, StopTrust};
use attest_envelope::{encode_pcr_selection, DEVICE_ID_LEN};
use attest_stop::{Kind, NONCE_MAX, NONCE_MIN};
use sha2::{Digest, Sha256};

/// What the stop service quotes (`PCR_SPEC` in crates/stop): sha256:0,1,8.
const PCRS: [u32; 3] = [0, 1, 8];
const BITMAP: [u8; 3] = [0x03, 0x01, 0x00];
const SHA256: u16 = 0x000B;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = match args.first().map(String::as_str) {
        Some("nonce") if args.len() == 1 => nonce().map(|()| 0),
        Some("check") => check(&args[1..]),
        _ => Err(USAGE.into()),
    };
    match r {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("tactiq-stop-verify: {e}");
            println!("VERDICT     REFUSED");
            ExitCode::from(1)
        }
    }
}

const USAGE: &str = "usage:\n  tactiq-stop-verify nonce\n  tactiq-stop-verify check RECEIPT --ak FILE --device ID \
                     --pcr-ref FILE [--slot A|B] (--nonce HEX | --no-nonce)";

fn nonce() -> Result<(), String> {
    use std::io::Read;
    let mut b = [0u8; 32];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .map_err(|e| format!("/dev/urandom: {e}"))?;
    println!("{}", hex(&b));
    Ok(())
}

struct Opts<'a> {
    receipt: &'a str,
    ak: &'a str,
    device: &'a str,
    pcr_ref: &'a str,
    slot: Option<&'a str>,
    nonce: Option<Vec<u8>>,
}

fn opts(a: &[String]) -> Result<Opts<'_>, String> {
    let receipt = a.first().filter(|s| !s.starts_with("--")).ok_or(USAGE)?;
    let (mut ak, mut device, mut pcr_ref, mut slot, mut nonce, mut no_nonce) = (None, None, None, None, None, false);
    let mut i = 1;
    while i < a.len() {
        let val = || a.get(i + 1).map(String::as_str).ok_or_else(|| format!("{} needs a value", a[i]));
        match a[i].as_str() {
            "--ak" => ak = Some(val()?),
            "--device" => device = Some(val()?),
            "--pcr-ref" => pcr_ref = Some(val()?),
            "--slot" => slot = Some(val()?),
            "--nonce" => nonce = Some(unhex(val()?)?),
            "--no-nonce" => {
                no_nonce = true;
                i += 1;
                continue;
            }
            other => return Err(format!("unknown option {other}\n{USAGE}")),
        }
        i += 2;
    }
    let nonce = match (nonce, no_nonce) {
        (Some(n), false) => {
            if n.len() < NONCE_MIN || n.len() > NONCE_MAX {
                return Err(format!("--nonce: {} bytes, must be {NONCE_MIN}..={NONCE_MAX}", n.len()));
            }
            Some(n)
        }
        (None, true) => None,
        _ => return Err("give exactly one of --nonce HEX and --no-nonce".into()),
    };
    Ok(Opts {
        receipt,
        ak: ak.ok_or("--ak is required")?,
        device: device.ok_or("--device is required")?,
        pcr_ref: pcr_ref.ok_or("--pcr-ref is required")?,
        slot,
        nonce,
    })
}

fn check(a: &[String]) -> Result<u8, String> {
    let o = opts(a)?;
    let receipt = fs::read(o.receipt).map_err(|e| format!("read {}: {e}", o.receipt))?;
    let ak_bytes = fs::read(o.ak).map_err(|e| format!("read {}: {e}", o.ak))?;
    let ak = AkKey::from_tpm2b_public(&ak_bytes).map_err(|e| format!("{}: {e}", o.ak))?;
    let ref_text = fs::read_to_string(o.pcr_ref).map_err(|e| format!("read {}: {e}", o.pcr_ref))?;
    let (composite, ref_note) = reference_composite(&ref_text, o.slot)?;
    let device_id = device_id(o.device)?;

    let f = verify_stop_receipt(
        &receipt,
        &StopTrust {
            ak: &ak,
            device_id,
            pcr_selection: encode_pcr_selection(SHA256, BITMAP),
            pcr_composite: composite,
            nonce: o.nonce.as_deref(),
        },
    )?;

    println!("receipt     {} ({} bytes)", o.receipt, receipt.len());
    println!("device      {}", o.device);
    println!("ak          name {}", hex(ak.name()));
    println!("build       PCR 0, 1, 8 equal to {}{ref_note}", o.pcr_ref);
    match &o.nonce {
        Some(n) => println!("fresh       yes: answers nonce {}", hex(n)),
        None => println!("fresh       no: no nonce, proves what was said, not when"),
    }
    match f.kind {
        Kind::Status => println!("kind        status answer"),
        Kind::Refusal { request_digest } => println!("kind        refusal of one call, request {}", hex(&request_digest)),
    }
    let parity = if f.stop_epoch % 2 == 1 { "odd" } else { "even" };
    println!("counter     {} ({parity}), read and signed by the TPM", f.stop_epoch);
    println!("policy      sha256 {}", hex(&f.policy_digest));
    let (verdict, code) = match f.basis() {
        StopBasis::Counter => {
            println!("basis       the counter is odd, as the TPM read it; in the build named above every call is refused at an odd counter");
            ("STOPPED", 0)
        }
        StopBasis::NoRelease => {
            println!("basis       even counter, the stop service found no valid operator release for it");
            ("STOPPED", 0)
        }
        StopBasis::Running => {
            println!("basis       even counter, the stop service found the operator's release for it");
            println!("            (the release itself is not in the receipt and was not checked here)");
            ("RUNNING", 2)
        }
    };
    let fresh = if f.fresh { "" } else { ", not fresh" };
    println!("VERDICT     {verdict}{fresh}");
    Ok(code)
}

/// SHA-256 over the reference values of PCR 0, 1 and 8, in that order: what
/// the TPM's `pcrDigest` is for a device booted into that build.
fn reference_composite(text: &str, slot: Option<&str>) -> Result<([u8; 32], String), String> {
    let doc: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("pcr reference: {e}"))?;
    let format = doc["format"].as_str().unwrap_or("");
    if format != "tactiq-pcr-reference/1" && format != "tactiq-pcr-reference/2" {
        return Err(format!("pcr reference: format {format:?}, want tactiq-pcr-reference/1 or /2"));
    }
    if doc["bank"].as_str() != Some("sha256") {
        return Err("pcr reference: bank is not sha256".into());
    }
    let mut h = Sha256::new();
    let mut per_slot = false;
    for i in PCRS {
        let v = &doc["pcr"][i.to_string()];
        let hexval = match (v, slot) {
            (serde_json::Value::String(s), _) => s.as_str(),
            (serde_json::Value::Object(m), Some(s)) => {
                per_slot = true;
                m.get(s)
                    .and_then(|x| x.as_str())
                    .ok_or_else(|| format!("pcr reference: PCR {i} has no value for slot {s}"))?
            }
            (serde_json::Value::Object(_), None) => {
                return Err(format!("pcr reference: PCR {i} differs per slot; give --slot"))
            }
            _ => return Err(format!("pcr reference: no PCR {i}")),
        };
        let b = unhex(hexval).map_err(|e| format!("pcr reference: PCR {i}: {e}"))?;
        if b.len() != 32 {
            return Err(format!("pcr reference: PCR {i} is {} bytes, want 32", b.len()));
        }
        h.update(&b);
    }
    let note = match (per_slot, slot) {
        (true, Some(s)) => format!(", slot {s}"),
        (false, Some(s)) => format!(" (same for every slot; --slot {s} not needed)"),
        _ => String::new(),
    };
    Ok((h.finalize().into(), note))
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

    fn doc(pcr1: &str) -> String {
        format!(r#"{{"format":"tactiq-pcr-reference/2","bank":"sha256","pcr":{{"0":"{ZERO}","1":{pcr1},"8":"{ZERO}"}}}}"#)
    }

    #[test]
    fn the_composite_is_over_pcr_0_1_8_in_order() {
        let (c, _) = reference_composite(&doc(&format!("\"{ZERO}\"")), None).unwrap();
        assert_eq!(c, <[u8; 32]>::from(Sha256::digest([0u8; 96])));
    }

    #[test]
    fn a_per_slot_pcr_needs_the_slot() {
        let one = "11".repeat(32);
        let d = doc(&format!(r#"{{"A":"{ZERO}","B":"{one}"}}"#));
        assert!(reference_composite(&d, None).is_err());
        assert!(reference_composite(&d, Some("C")).is_err());
        let (a, _) = reference_composite(&d, Some("A")).unwrap();
        let (b, _) = reference_composite(&d, Some("B")).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn another_format_or_bank_is_refused() {
        let d = doc(&format!("\"{ZERO}\""));
        assert!(reference_composite(&d.replace("reference/2", "reference/9"), None).is_err());
        assert!(reference_composite(&d.replace("\"sha256\"", "\"sha1\""), None).is_err());
        assert!(reference_composite(&d.replace(&format!("\"8\":\"{ZERO}\""), "\"8\":\"00\""), None).is_err());
    }
}
