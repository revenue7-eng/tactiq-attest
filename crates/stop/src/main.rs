//! tactiq-stop: the agent stop service.
//!
//! agentgateway asks it before every tool call (`extAuthz`, http mode). The
//! answer is decided by one TPM NV counter whose parity is the stop state
//! (odd = stopped). A refusal carries a receipt the TPM signed: the AK quote
//! over the boot PCRs, and the TPM's own `NV_Certify` of the counter, both
//! bound to the stop record, which the service checks before handing it out.
//!
//! Commands
//!   serve                          answer the gateway on 127.0.0.1:49318
//!   status [nonce-hex]             write a signed status receipt (nonce 32..128 hex chars)
//!   trip                           stop the agent (idempotent), then confirm through the service
//!   recover                        lift the stop (idempotent), then confirm through the service
//!   define [--initial stopped|running]   create the stop counter (default: stopped)
//!
//! Paths, the index and the listener are fixed in the binary, not taken from
//! the environment, so the service and the operator commands cannot end up
//! looking at different counters or different locks.
//!
//! Known limits of this version, stated rather than hidden:
//!   * the counter is written with the owner hierarchy, whose auth is empty
//!     on TactiQ OS, so any process with TPM access can trip or recover, and
//!     the owner can delete and redefine the index. An operator policy on
//!     the index is the next step;
//!   * the AK is shared with tactiq-agent and has no authorization, so a
//!     valid receipt proves the device and its measured build, not which
//!     process on it asked for the signatures;
//!   * a release image gives no shell, so trip and recover have no operator
//!     channel there yet;
//!   * a call whose check finished just before `trip` returned was allowed:
//!     a stop applies to checks that begin after `trip` returns.

mod config;
mod core;
mod http;
mod port;

use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use attest_stop::State;
use sha2::{Digest, Sha256};

use crate::core::{Admission, Ctx, Transition, TransitionError};
use crate::port::{Real, StopTpm};

const LISTEN: &str = "127.0.0.1:49318";
const KEYS_DIR: &str = "/data/tactiq/keys";
const WORK_DIR: &str = "/run/tactiq-stop";
/// Boot measurements: bootloader (0), the signed device tree with the kernel
/// command line and the dm-verity root hash, which covers the whole root
/// filesystem including agentgateway and this service (1), the kernel (8).
const PCR_SPEC: &str = "sha256:0,1,8";
const POLICY: &str = "/etc/tactiq/agentgateway/config.yaml";
const DEVICE_ID_LEN: usize = attest_envelope::DEVICE_ID_LEN;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    let r = match cmd {
        "serve" => serve(),
        "status" => cmd_status(args.get(2).map(String::as_str)),
        "trip" => admin(core::trip, State::Stopped),
        "recover" => admin(core::recover, State::Running),
        "define" => define(&args[2..]),
        _ => Err("usage: tactiq-stop serve | status [nonce-hex] | trip | recover | define [--initial stopped|running]".into()),
    };
    if let Err(e) = r {
        eprintln!("tactiq-stop: {e}");
        std::process::exit(1);
    }
}

/// The shared work directory: created 0700, and refused if it belongs to
/// someone else or is open to others. Anyone who can write here could plant
/// tool outputs.
fn work_dir() -> Result<PathBuf, String> {
    let w = PathBuf::from(WORK_DIR);
    if !w.exists() {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&w)
            .map_err(|e| format!("create {WORK_DIR}: {e}"))?;
    }
    let md = fs::symlink_metadata(&w).map_err(|e| format!("stat {WORK_DIR}: {e}"))?;
    let me = fs::metadata("/proc/self").map_err(|e| format!("stat /proc/self: {e}"))?.uid();
    if !md.is_dir() || md.uid() != me || md.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "{WORK_DIR} must be a directory owned by uid {me} with mode 0700 (is uid {}, mode {:o})",
            md.uid(),
            md.permissions().mode() & 0o7777
        ));
    }
    Ok(w)
}

/// A scratch directory private to this process, removed on drop. The TPM
/// tools write their outputs here, so no other process can swap them.
struct Scratch(PathBuf);

impl Scratch {
    fn new(work: &Path) -> Result<Self, String> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = work.join(format!("p{}-{nanos}", std::process::id()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&p)
            .map_err(|e| format!("create {}: {e}", p.display()))?;
        Ok(Scratch(p))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
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

struct Owned {
    device_id: String,
    pcr_alg: u16,
    pcr_bitmap: [u8; 3],
    policy: [u8; 32],
    index_name: Vec<u8>,
}

impl Owned {
    fn load(scratch: &Path) -> Result<Self, String> {
        let keys = PathBuf::from(KEYS_DIR);
        let device_id = read_device_id(&keys)?;
        // Never sign with whatever happens to sit at the AK handle.
        attest_tpm::verify_ak(&keys.join("ak.pub"), scratch)?;
        attest_tpm::verify_stop_counter()?;
        let index_name = attest_tpm::stop_nv_name()?;
        let (pcr_alg, pcr_bitmap) = attest_tpm::parse_pcr_spec(PCR_SPEC)?;
        // The policy file is read once: it lives on the dm-verity root and
        // cannot change under a running service without a reboot into
        // another measured build.
        let text = fs::read(POLICY).map_err(|e| format!("read {POLICY}: {e}"))?;
        config::check_gateway_config(&String::from_utf8_lossy(&text), LISTEN)?;
        Ok(Owned {
            device_id,
            pcr_alg,
            pcr_bitmap,
            policy: Sha256::digest(&text).into(),
            index_name,
        })
    }

    fn ctx(&self) -> Ctx<'_> {
        Ctx {
            device_id: &self.device_id,
            pcr_spec: PCR_SPEC,
            pcr_alg: self.pcr_alg,
            pcr_bitmap: self.pcr_bitmap,
            policy_digest: self.policy,
            stop_index_name: &self.index_name,
        }
    }
}

fn serve() -> Result<(), String> {
    let work = work_dir()?;
    let scratch = Scratch::new(&work)?;
    let owned = Owned::load(&scratch.0)?;
    let tpm = Real { scratch: &scratch.0 };
    let l = TcpListener::bind(LISTEN).map_err(|e| format!("bind {LISTEN}: {e}"))?;
    eprintln!("tactiq-stop: serving on {LISTEN}, state {:?}", core::state_of(tpm.read_counter()?));
    for conn in l.incoming() {
        match conn {
            Ok(mut s) => handle(&mut s, &tpm, &owned.ctx()),
            // Do not spin on a persistent accept error.
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    Ok(())
}

/// One gateway question, one answer. Every path that is not a clean
/// "running" ends in a non-2xx response, which the gateway treats as deny.
fn handle(s: &mut TcpStream, tpm: &dyn StopTpm, ctx: &Ctx) {
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
    if !s.bytes().all(|b| b.is_ascii_hexdigit()) || !s.len().is_multiple_of(2) {
        return Err("nonce: must be an even number of hex digits".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "nonce: not hex".to_string()))
        .collect()
}

/// Exclusive lock for every command that changes or certifies the counter.
fn admin_lock(work: &Path) -> Result<File, String> {
    let p = work.join("admin.lock");
    let f = File::create(&p).map_err(|e| format!("create {}: {e}", p.display()))?;
    f.lock().map_err(|e| format!("lock {}: {e}", p.display()))?;
    Ok(f)
}

fn cmd_status(nonce_hex: Option<&str>) -> Result<(), String> {
    let nonce = match nonce_hex {
        Some(h) => hex_decode(h)?,
        None => Vec::new(),
    };
    let work = work_dir()?;
    let _lock = admin_lock(&work)?;
    let scratch = Scratch::new(&work)?;
    let owned = Owned::load(&scratch.0)?;
    let tpm = Real { scratch: &scratch.0 };
    let receipt = core::status(&tpm, &owned.ctx(), &nonce)?;
    let out = PathBuf::from("stop-status.tqsr");
    fs::write(&out, &receipt).map_err(|e| format!("write {}: {e}", out.display()))?;
    println!("status receipt -> {}", out.display());
    Ok(())
}

fn admin(f: fn(&dyn StopTpm) -> Result<Transition, TransitionError>, want: State) -> Result<(), String> {
    let work = work_dir()?;
    let _lock = admin_lock(&work)?;
    attest_tpm::verify_stop_counter()?;
    let scratch = Scratch::new(&work)?;
    let tpm = Real { scratch: &scratch.0 };
    match f(&tpm) {
        Ok(Transition::Changed { from, to }) => {
            println!("stop counter {from} -> {to}: {:?}", core::state_of(to))
        }
        Ok(Transition::AlreadyThere { at }) => {
            println!("stop counter {at}: already {:?}, nothing done", core::state_of(at))
        }
        Err(e) => return Err(describe_failure(&e)),
    }
    confirm_through_service(want)
}

/// Make an operator failure impossible to misread.
fn describe_failure(e: &TransitionError) -> String {
    match e.now {
        Some(c) => format!(
            "{}\nTHE AGENT IS NOW {:?} (stop counter {c})",
            e.message,
            core::state_of(c)
        ),
        None => format!("{}\nTHE AGENT'S STATE IS UNKNOWN: the counter could not be read", e.message),
    }
}

/// Ask the running service what it now answers. The counter is the truth,
/// but this catches a service that is not looking at it.
fn confirm_through_service(want: State) -> Result<(), String> {
    let mut s = match TcpStream::connect(LISTEN) {
        Ok(s) => s,
        Err(_) => {
            println!(
                "service not reachable on {LISTEN}; while it is down the gateway denies every call (failureMode deny)"
            );
            return Ok(());
        }
    };
    s.set_read_timeout(Some(Duration::from_secs(15))).map_err(|e| e.to_string())?;
    s.write_all(b"POST /tactiq-stop/probe HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
        .map_err(|e| format!("probe: {e}"))?;
    let mut out = Vec::new();
    s.read_to_end(&mut out).map_err(|e| format!("probe: {e}"))?;
    let code = String::from_utf8_lossy(out.get(9..12).unwrap_or(b"???")).to_string();
    match (want, code.as_str()) {
        (State::Stopped, "403") => {
            println!("service confirms: calls are refused");
            Ok(())
        }
        (State::Running, "200") => {
            println!("service confirms: calls pass");
            Ok(())
        }
        (State::Stopped, "200") => Err("THE SERVICE STILL ANSWERS 200: tool calls are NOT stopped".into()),
        (_, c) => Err(format!("service answered {c}, not what {want:?} should give")),
    }
}

fn define(args: &[String]) -> Result<(), String> {
    let want = match args {
        [] => State::Stopped,
        [flag, v] if flag == "--initial" && v == "stopped" => State::Stopped,
        [flag, v] if flag == "--initial" && v == "running" => State::Running,
        _ => return Err("define takes --initial stopped|running".into()),
    };
    let work = work_dir()?;
    let _lock = admin_lock(&work)?;
    let nv = attest_tpm::STOP_NV_COUNTER;
    if attest_tpm::nv_defined(nv)? {
        attest_tpm::verify_stop_counter()?;
        return Err(format!("{nv} already defined; use trip or recover to change the state"));
    }
    attest_tpm::stop_nv_define()?;
    attest_tpm::verify_stop_counter()?;
    let scratch = Scratch::new(&work)?;
    let tpm = Real { scratch: &scratch.0 };
    // The TPM chose the first value; its parity is not ours. Set the state
    // the operator asked for, with at most one increment.
    match core::settle(&tpm, want) {
        Ok(Transition::Changed { from, to }) => println!(
            "{nv} defined; started at {from}, moved to {to}: {:?}",
            core::state_of(to)
        ),
        Ok(Transition::AlreadyThere { at }) => {
            println!("{nv} defined at {at}: {:?}", core::state_of(at))
        }
        Err(e) => return Err(describe_failure(&e)),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! The loop as the gateway sees it: a real loopback socket, the fake TPM.

    use super::*;
    use crate::port::fake::{Fake, INDEX_NAME};

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
            pcr_spec: PCR_SPEC,
            pcr_alg: 0x000B,
            pcr_bitmap: [0x03, 0x01, 0x00],
            policy_digest: [0x11; 32],
            stop_index_name: &INDEX_NAME,
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
        t.fail_reads_from.set(Some(1));
        assert_eq!(ask(&t, CALL).0, 503);
    }

    #[test]
    fn moved_counter_answers_503_without_a_receipt() {
        let t = Fake::at(3);
        t.move_before_certify.set(true);
        assert_eq!(ask(&t, CALL), (503, b"stop state unavailable".to_vec()));
    }

    #[test]
    fn malformed_or_extra_input_answers_400_which_is_a_deny() {
        assert_eq!(ask(&Fake::at(2), b"POST /mcp HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").0, 400);
        let two = b"POST /mcp HTTP/1.1\r\nContent-Length: 0\r\n\r\nGET / HTTP/1.1\r\n\r\n";
        assert_eq!(ask(&Fake::at(2), two).0, 400);
    }

    #[test]
    fn a_silent_client_is_dropped_within_the_deadline() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let _c = TcpStream::connect(addr).unwrap();
        let (mut s, _) = l.accept().unwrap();
        let t0 = std::time::Instant::now();
        assert!(http::read_request(&mut s).is_err());
        assert!(t0.elapsed() < http::REQUEST_DEADLINE + Duration::from_secs(1));
    }

    #[test]
    fn nonce_hex_refuses_non_ascii_without_panicking() {
        assert!(hex_decode("é0").is_err());
        assert!(hex_decode("abc").is_err());
        assert_eq!(hex_decode("00ff").unwrap(), vec![0, 255]);
    }

    #[test]
    fn failure_messages_state_the_agent_state() {
        let e = TransitionError { message: "x".into(), now: Some(6) };
        assert!(describe_failure(&e).contains("THE AGENT IS NOW Running"));
        let e = TransitionError { message: "x".into(), now: None };
        assert!(describe_failure(&e).contains("UNKNOWN"));
    }
}
