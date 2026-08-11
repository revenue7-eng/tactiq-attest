//! tactiq-agent — the prover side of Custinel attestation.
//!
//! Produces the canonical envelope that `attest-core` verifies:
//!
//!     device_id(16) || counter_be(8) || pcr_selection(5) || pcr_hash(32)   = 61 bytes
//!
//! The envelope is built by `attest-core::build_canonical`, not by this crate.
//! That is the point of depending on it: prover and verifier share one codec, so
//! the two sides cannot drift apart in layout, field order, or padding. The
//! earlier documents described the envelope as `device_id + counter + pcr_hash +
//! timestamp` signed with Ed25519; both were wrong against the code, and reusing
//! the codec is what makes that class of mistake impossible rather than merely
//! unlikely.
//!
//! Commands
//!   provision   first boot: create key, define counter, assign identity
//!   attest      one cycle: advance counter, measure, build envelope, sign
//!   run         attest on an interval, feeding the systemd watchdog
//!
//! Everything TPM-facing is in `tpm.rs`; everything disk-facing is in `state.rs`.

mod state;
mod tpm;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use attest_envelope::{build_canonical, encode_pcr_selection, MSG_LEN};
use state::{Paths, Provisioning};

/// SHA-256 over PCRs 0..7. Alg 0x000B is sha256; the bitmap is little-endian by
/// PCR index (PCR n -> byte n/8, bit n%8), so 0..7 is `ff 00 00`.
///
/// This pair is not a constant of the protocol: `verifier-rats` compares the
/// selection against the reference set's `expected_selection` before it compares
/// the composite, so the selection is a property of the platform profile. It is
/// a default here, overridable, and the value that ends up in the golden set is
/// whatever the device actually sends at enrolment.
const DEFAULT_PCR_SPEC: &str = "sha256:0,1,2,3,4,5,6,7";
const DEFAULT_PCR_ALG: u16 = 0x000B;
const DEFAULT_PCR_BITMAP: [u8; 3] = [0xff, 0x00, 0x00];

const DEFAULT_KEYS_DIR: &str = "/data/tactiq/keys";
const DEFAULT_OUT_DIR: &str = "/data/tactiq/audit";
const DEFAULT_WORK_DIR: &str = "/run/tactiq-agent";
const DEFAULT_INTERVAL_SECS: u64 = 30;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");

    let keys_dir = env_or("TACTIQ_KEYS_DIR", DEFAULT_KEYS_DIR);
    let out_dir = env_or("TACTIQ_OUT_DIR", DEFAULT_OUT_DIR);
    let work_dir = env_or("TACTIQ_WORK_DIR", DEFAULT_WORK_DIR);
    let pcr_spec = env_or("TACTIQ_PCR_SPEC", DEFAULT_PCR_SPEC);

    let paths = Paths::new(&keys_dir);
    let work = PathBuf::from(&work_dir);

    let r = match cmd {
        "provision" => {
            let id = match args.get(2) {
                Some(v) => v.clone(),
                None => {
                    eprintln!("usage: tactiq-agent provision <device-id>");
                    std::process::exit(2);
                }
            };
            cmd_provision(&paths, &work, &id)
        }
        "attest" => cmd_attest(&paths, &work, &out_dir, &pcr_spec).map(|_| ()),
        "run" => {
            let secs: u64 = env_or("TACTIQ_INTERVAL_SECS", &DEFAULT_INTERVAL_SECS.to_string())
                .parse()
                .unwrap_or(DEFAULT_INTERVAL_SECS);
            cmd_run(&paths, &work, &out_dir, &pcr_spec, Duration::from_secs(secs))
        }
        "status" => cmd_status(&paths),
        _ => {
            eprintln!(
                "tactiq-agent <command>\n\
                 \n\
                   provision <device-id>   first boot: key, counter, identity\n\
                   attest                  emit one signed envelope\n\
                   run                     attest on an interval (systemd)\n\
                   status                  report provisioning state\n\
                 \n\
                 env: TACTIQ_KEYS_DIR TACTIQ_OUT_DIR TACTIQ_WORK_DIR\n\
                      TACTIQ_PCR_SPEC TACTIQ_INTERVAL_SECS"
            );
            std::process::exit(2);
        }
    };

    if let Err(e) = r {
        eprintln!("tactiq-agent: {e}");
        // Fail closed: a non-zero exit is what makes systemd stop the unit
        // rather than let a device that cannot attest keep running as if it can.
        std::process::exit(1);
    }
}

fn ensure_dir(p: &Path) -> Result<(), String> {
    fs::create_dir_all(p).map_err(|e| format!("mkdir {}: {e}", p.display()))
}

fn cmd_status(paths: &Paths) -> Result<(), String> {
    match state::inspect(paths) {
        Provisioning::Complete => {
            println!("provisioned: {}", state::read_id(paths)?);
            Ok(())
        }
        Provisioning::Absent => {
            println!("unprovisioned");
            Ok(())
        }
        Provisioning::Partial { have_id, have_key } => Err(format!(
            "partial provisioning state (device_id: {have_id}, pubkey: {have_key}) — \
             refusing to continue; re-provision this device at the verifier and \
             clear {} deliberately",
            paths.keys_dir.display()
        )),
    }
}

fn cmd_provision(paths: &Paths, work: &Path, id: &str) -> Result<(), String> {
    state::validate_id(id)?;
    ensure_dir(&paths.keys_dir)?;
    ensure_dir(work)?;

    match state::inspect(paths) {
        Provisioning::Complete => {
            let existing = state::read_id(paths)?;
            return Err(format!(
                "already provisioned as {existing}; provisioning again would strand \
                 the key the verifier holds under that id"
            ));
        }
        Provisioning::Partial { have_id, have_key } => {
            return Err(format!(
                "partial provisioning state (device_id: {have_id}, pubkey: {have_key}) — \
                 not repairing automatically"
            ));
        }
        Provisioning::Absent => {}
    }

    // The TPM may already hold objects from an interrupted run. Reuse rather
    // than recreate: evicting and recreating the key would invalidate a public
    // key the verifier may already have been given.
    if !tpm::handle_exists(tpm::PARENT_HANDLE) {
        tpm::create_primary(work)?;
    }
    if !tpm::handle_exists(tpm::KEY_HANDLE) {
        tpm::create_signing_key(work)?;
    }
    if !tpm::nv_defined(tpm::NV_COUNTER) {
        tpm::nv_define()?;
    }

    // Key first, then id. A crash between the two leaves "key, no id", which
    // `inspect` reports as Partial and every command refuses to run on. The
    // reverse order would leave an id with no key, which looks the same from
    // outside but is harder to reason about: the id may already have been
    // handed to the verifier.
    tpm::read_public_pem(&paths.pubkey())?;
    state::finalize_pubkey_perms(paths)?;
    state::sync_dir(&paths.keys_dir)?;
    state::write_id(paths, id)?;

    println!("provisioned {id}");
    println!("  public key: {}", paths.pubkey().display());
    println!("  give that file to the verifier as trust/{id}.pem");
    Ok(())
}

/// One attestation cycle. Returns the counter value the envelope carries.
fn cmd_attest(paths: &Paths, work: &Path, out_dir: &str, pcr_spec: &str) -> Result<u64, String> {
    ensure_dir(work)?;
    let out = PathBuf::from(out_dir);
    ensure_dir(&out)?;

    let id = match state::inspect(paths) {
        Provisioning::Complete => state::read_id(paths)?,
        Provisioning::Absent => return Err("not provisioned; run `tactiq-agent provision <id>`".into()),
        Provisioning::Partial { have_id, have_key } => {
            return Err(format!(
                "partial provisioning state (device_id: {have_id}, pubkey: {have_key})"
            ))
        }
    };

    // Order matters: advance the counter before measuring. If the process dies
    // after the increment, the burned value is simply never used — a gap in the
    // sequence is harmless because the verifier requires strictly-greater, not
    // consecutive. Measuring first and incrementing after would allow two
    // envelopes to describe different states under one counter value.
    let counter = tpm::nv_increment_and_read(work)?;
    let pcr_state = tpm::pcr_read(pcr_spec, work)?;
    let selection = encode_pcr_selection(DEFAULT_PCR_ALG, DEFAULT_PCR_BITMAP);

    let msg = build_canonical(&id, counter, &selection, &pcr_state);
    if msg.len() != MSG_LEN {
        return Err(format!("built {} bytes, expected {MSG_LEN}", msg.len()));
    }

    let stem = format!("{counter:012}");
    let msg_path = out.join(format!("{stem}.msg"));
    let sig_path = out.join(format!("{stem}.sig"));
    fs::write(&msg_path, &msg).map_err(|e| format!("write {}: {e}", msg_path.display()))?;
    tpm::sign(&msg_path, &sig_path)?;
    // The tag file is what `custinel-verify` reads to decide the expected
    // disposition; a real emission always expects Accept.
    fs::write(out.join(format!("{stem}.tag")), format!("{id} counter={counter}\n"))
        .map_err(|e| format!("write tag: {e}"))?;

    println!("attested {id} counter={counter} -> {}", msg_path.display());
    Ok(counter)
}

/// Notify systemd. Written by hand rather than pulling a crate in: it is one
/// datagram, and the agent is TCB code where every dependency is a liability.
///
/// The unit sets `WatchdogSec=120` with `Type=simple`, which means systemd
/// expects `WATCHDOG=1` and will kill the service if it stops arriving. The stub
/// never sent it, which is why it would have been restarted every two minutes
/// had it ever been enabled.
fn sd_notify(msg: &str) {
    let sock = match std::env::var("NOTIFY_SOCKET") {
        Ok(s) => s,
        Err(_) => return, // not under systemd
    };
    if sock.starts_with('@') {
        // Abstract namespace: std has no stable API for it. systemd uses a
        // filesystem path for services by default, so this is a note, not a gap
        // worth an unsafe block.
        eprintln!("tactiq-agent: abstract NOTIFY_SOCKET unsupported, watchdog not fed");
        return;
    }
    if let Ok(s) = std::os::unix::net::UnixDatagram::unbound() {
        let _ = s.send_to(msg.as_bytes(), &sock);
    }
}

fn cmd_run(
    paths: &Paths,
    work: &Path,
    out_dir: &str,
    pcr_spec: &str,
    interval: Duration,
) -> Result<(), String> {
    // Refuse to start at all on a bad identity, rather than starting and
    // failing every cycle.
    match state::inspect(paths) {
        Provisioning::Complete => {}
        other => return Err(format!("cannot run: {other:?}")),
    }

    sd_notify("READY=1");
    loop {
        let started = Instant::now();
        match cmd_attest(paths, work, out_dir, pcr_spec) {
            Ok(_) => sd_notify("WATCHDOG=1"),
            Err(e) => {
                // Deliberately not fed on failure: an agent that cannot attest
                // should be seen as down by systemd, not linger as a healthy
                // process producing nothing.
                eprintln!("tactiq-agent: attest failed: {e}");
                sd_notify(&format!("STATUS=attest failed: {e}"));
                return Err(e);
            }
        }
        let elapsed = started.elapsed();
        if elapsed < interval {
            std::thread::sleep(interval - elapsed);
        }
    }
}
