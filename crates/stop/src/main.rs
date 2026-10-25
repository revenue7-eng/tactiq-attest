//! tactiq-stop: the agent stop service.
//!
//! agentgateway asks it before every tool call (`extAuthz`, http mode). The
//! answer is decided by one TPM NV counter whose parity is the stop state
//! (odd = stopped), and every refusal carries a receipt the TPM signed:
//!
//!   * the AK quote over the boot PCRs says which measured build answered;
//!   * `TPM2_NV_Certify` gives the TPM's own reading of the stop counter;
//!   * both are bound to the stop record, and a status answer to the
//!     verifier's nonce, so none of them can be moved to another answer.
//!
//! Commands
//!   serve            answer the gateway on TACTIQ_STOP_LISTEN
//!   status [nonce]   write a signed status receipt (nonce: 32..128 hex chars)
//!   trip             stop the agent (idempotent)
//!   recover          lift the stop (idempotent)
//!   define           create the stop counter in the TPM (first boot)
//!
//! What this version does not do yet: an operator channel on a release image
//! (trip and recover need a shell, which a release image does not give), and
//! operator-signed authorization of the counter write. Today the counter is
//! written with the owner hierarchy, as the agent's counter is; the agent
//! itself cannot reach the TPM at all (SELinux), but the service could.

mod core;
mod http;
mod port;

use std::fs::{self, File};
use std::net::TcpListener;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::core::{Admission, Ctx, Transition};
use crate::port::{Real, StopTpm};

const DEFAULT_LISTEN: &str = "127.0.0.1:49318";
const DEFAULT_KEYS_DIR: &str = "/data/tactiq/keys";
const DEFAULT_WORK_DIR: &str = "/run/tactiq-stop";
/// Boot measurements: bootloader (0), the signed device tree with the kernel
/// command line and the dm-verity root hash, which is to say the whole root
/// filesystem including agentgateway and this service (1), the kernel (8).
const DEFAULT_PCR_SPEC: &str = "sha256:0,1,8";
const DEFAULT_POLICY: &str = "/etc/tactiq/agentgateway/config.yaml";
const DEVICE_ID_LEN: usize = attest_envelope::DEVICE_ID_LEN;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    let r = match cmd {
        "serve" => serve(),
        "status" => cmd_status(args.get(2).map(String::as_str)),
        "trip" => admin(crate::core::trip),
        "recover" => admin(crate::core::recover),
        "define" => define(),
        _ => Err("usage: tactiq-stop serve | status [nonce-hex] | trip | recover | define".into()),
    };
    if let Err(e) = r {
        eprintln!("tactiq-stop: {e}");
        std::process::exit(1);
    }
}

fn work_dir() -> Result<PathBuf, String> {
    let w = PathBuf::from(env_or("TACTIQ_WORK_DIR", DEFAULT_WORK_DIR));
    fs::create_dir_all(&w).map_err(|e| format!("create {}: {e}", w.display()))?;
    Ok(w)
}

/// The device id the agent provisioned, read-only. Same rules as the agent's.
fn read_device_id(keys: &Path) -> Result<String, String> {
    let p = keys.join("device_id");
    let id = fs::read_to_string(&p)
        .map_err(|e| format!("read {}: {e}", p.display()))?
        .trim()
        .to_string();
    if id.is_empty() || id.len() > DEVICE_ID_LEN || !id.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!("{}: not a valid device id", p.display()));
    }
    Ok(id)
}

/// SHA-256 of the gateway policy the service is enforcing. Read once at
/// start: the file lives on the dm-verity root, so it cannot change under a
/// running service without a reboot into another measured build.
fn policy_digest() -> Result<[u8; 32], String> {
    let p = env_or("TACTIQ_STOP_POLICY", DEFAULT_POLICY);
    let b = fs::read(&p).map_err(|e| format!("read policy {p}: {e}"))?;
    Ok(Sha256::digest(&b).into())
}

struct Owned {
    device_id: String,
    pcr_spec: String,
    pcr_alg: u16,
    pcr_bitmap: [u8; 3],
    policy: [u8; 32],
}

impl Owned {
    fn load(work: &Path) -> Result<Self, String> {
        let keys = PathBuf::from(env_or("TACTIQ_KEYS_DIR", DEFAULT_KEYS_DIR));
        let device_id = read_device_id(&keys)?;
        // Never sign with whatever happens to sit at the AK handle.
        attest_tpm::verify_ak(&keys.join("ak.pub"), work)?;
        attest_tpm::verify_stop_counter()?;
        let pcr_spec = env_or("TACTIQ_STOP_PCR_SPEC", DEFAULT_PCR_SPEC);
        let (pcr_alg, pcr_bitmap) = attest_tpm::parse_pcr_spec(&pcr_spec)?;
        Ok(Owned { device_id, pcr_spec, pcr_alg, pcr_bitmap, policy: policy_digest()? })
    }

    fn ctx(&self) -> Ctx<'_> {
        Ctx {
            device_id: &self.device_id,
            pcr_spec: &self.pcr_spec,
            pcr_alg: self.pcr_alg,
            pcr_bitmap: self.pcr_bitmap,
            policy_digest: self.policy,
        }
    }
}

fn serve() -> Result<(), String> {
    let work = work_dir()?;
    let owned = Owned::load(&work)?;
    let tpm = Real { work: &work };
    let listen = env_or("TACTIQ_STOP_LISTEN", DEFAULT_LISTEN);
    let l = TcpListener::bind(&listen).map_err(|e| format!("bind {listen}: {e}"))?;
    eprintln!("tactiq-stop: serving on {listen}, state {:?}", core::state_of(tpm.read_counter()?));
    for conn in l.incoming() {
        let Ok(mut s) = conn else { continue };
        handle(&mut s, &tpm, &owned.ctx());
    }
    Ok(())
}

/// One gateway question, one answer. Every path that is not a clean
/// "running" ends in a non-2xx response, which the gateway treats as deny.
fn handle(s: &mut std::net::TcpStream, tpm: &dyn StopTpm, ctx: &Ctx) {
    let (code, ctype, body) = match http::read_request(s) {
        Err(e) => (400, "text/plain", e.into_bytes()),
        Ok(req) => {
            let d = attest_stop::request_digest(&req.method, &req.path, &req.body);
            match core::admit(tpm, ctx, d) {
                Ok(Admission::Allow) => (200, "text/plain", Vec::new()),
                Ok(Admission::Refuse(receipt)) => (403, "application/octet-stream", receipt),
                Err(e) => {
                    eprintln!("tactiq-stop: refusing, cannot decide: {e}");
                    (503, "text/plain", b"stop state unavailable".to_vec())
                }
            }
        }
    };
    let _ = http::respond(s, code, ctype, &body);
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("nonce: odd number of hex digits".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "nonce: not hex".to_string()))
        .collect()
}

fn cmd_status(nonce_hex: Option<&str>) -> Result<(), String> {
    let nonce = match nonce_hex {
        Some(h) => hex_decode(h)?,
        None => Vec::new(),
    };
    let work = work_dir()?;
    let owned = Owned::load(&work)?;
    let tpm = Real { work: &work };
    let receipt = core::status(&tpm, &owned.ctx(), &nonce)?;
    let out = PathBuf::from(env_or("TACTIQ_STOP_OUT", "stop-status.tqsr"));
    fs::write(&out, &receipt).map_err(|e| format!("write {}: {e}", out.display()))?;
    let c = tpm.read_counter()?;
    println!("state {:?} epoch {c} -> {}", core::state_of(c), out.display());
    Ok(())
}

/// Run an operator transition under an exclusive lock, so two operator
/// commands cannot interleave their read and increment.
fn admin(f: fn(&dyn StopTpm) -> Result<Transition, String>) -> Result<(), String> {
    let work = work_dir()?;
    attest_tpm::verify_stop_counter()?;
    let lock_path = work.join("admin.lock");
    let lock = File::create(&lock_path).map_err(|e| format!("create {}: {e}", lock_path.display()))?;
    lock.lock().map_err(|e| format!("lock {}: {e}", lock_path.display()))?;
    let tpm = Real { work: &work };
    match f(&tpm)? {
        Transition::Changed { from, to } => {
            println!("stop counter {from} -> {to}: {:?}", core::state_of(to))
        }
        Transition::AlreadyThere { at } => {
            println!("stop counter {at}: already {:?}, nothing done", core::state_of(at))
        }
    }
    Ok(())
}

fn define() -> Result<(), String> {
    let work = work_dir()?;
    let nv = attest_tpm::stop_nv_counter()?;
    if attest_tpm::nv_defined(&nv)? {
        attest_tpm::verify_stop_counter()?;
        println!("{nv} already defined");
    } else {
        attest_tpm::stop_nv_define()?;
        println!("{nv} defined");
    }
    let tpm = Real { work: &work };
    let c = tpm.read_counter()?;
    println!("stop counter {c}: {:?}", core::state_of(c));
    Ok(())
}

#[cfg(test)]
mod tests {
    //! The loop as the gateway sees it: a real loopback socket, the fake TPM.

    use super::*;
    use crate::port::fake::Fake;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    fn ask(tpm: &Fake, raw: &[u8]) -> (u16, Vec<u8>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let raw = raw.to_vec();
        let client = std::thread::spawn(move || {
            let mut c = TcpStream::connect(addr).unwrap();
            c.write_all(&raw).unwrap();
            let mut out = Vec::new();
            c.read_to_end(&mut out).unwrap();
            out
        });
        let (mut s, _) = l.accept().unwrap();
        let ctx = Ctx {
            device_id: "device-A",
            pcr_spec: "sha256:0,1,8",
            pcr_alg: 0x000B,
            pcr_bitmap: [0x03, 0x01, 0x00],
            policy_digest: [0x11; 32],
        };
        handle(&mut s, tpm, &ctx);
        drop(s);
        let out = client.join().unwrap();
        let text = String::from_utf8_lossy(&out);
        let code: u16 = text[9..12].parse().unwrap();
        let split = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        (code, out[split..].to_vec())
    }

    const CALL: &[u8] = b"POST /mcp HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}";

    #[test]
    fn running_answers_200() {
        assert_eq!(ask(&Fake::at(2), CALL), (200, Vec::new()));
    }

    #[test]
    fn stopped_answers_403_with_a_receipt_for_this_call() {
        let (code, body) = ask(&Fake::at(3), CALL);
        assert_eq!(code, 403);
        let r = attest_stop::Receipt::parse(&body).unwrap();
        let s = attest_envelope::parse_bundle(&r.bundle).unwrap();
        let rec = attest_stop::StopRecord::parse(s[0].body).unwrap();
        assert_eq!(
            rec.kind,
            attest_stop::Kind::Refusal {
                request_digest: attest_stop::request_digest("POST", "/mcp", b"{}")
            }
        );
    }

    #[test]
    fn unreadable_state_answers_503_which_is_a_deny() {
        let t = Fake::at(2);
        t.fail_read.set(true);
        assert_eq!(ask(&t, CALL).0, 503);
    }

    #[test]
    fn malformed_request_answers_400_which_is_a_deny() {
        let raw = b"POST /mcp HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(ask(&Fake::at(2), raw).0, 400);
    }
}
