//! tactiq-agent — the prover side of Custinel attestation.
//!
//! Produces the canonical envelope that `attest-core` verifies:
//!
//!     device_id(16) || counter_be(8) || pcr_selection(5) || pcr_hash(32) || evidence_hash(32) = 93 bytes
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
//!   provision   first boot: create AK under the EK, define counter, assign identity
//!   attest      one cycle: take an epoch, measure, build envelope, quote
//!
//! Envelope v2 (DDR-004): `<stem>.msg` is the 93-byte message above,
//! `<stem>.attest` the `TPMS_ATTEST` of a TPM quote whose qualifying data is
//! SHA-256 of the message, `<stem>.sig` the AK signature over `.attest`.
//!   run         attest on an interval, feeding the systemd watchdog
//!   status      report provisioning state and whether the AK is in place
//!
//! The AK lives at `tpm::ak_handle()` in the endorsement hierarchy (DDR-005).
//! The agent never adopts an object because it occupies that handle: before
//! every use it compares the object's name with the AK public area recorded at
//! provisioning (`keys/ak.pub`), and refuses on any difference.
//!
//! Everything TPM-facing is in `tpm.rs`; everything disk-facing is in `state.rs`.

mod state;
mod tpm;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use attest_envelope::{build_canonical, encode_pcr_selection, MSG_LEN};
use state::{Paths, Provisioning};

/// The PCR selection the prover attests, as a tpm2-tools selection string.
///
/// This is the ONLY source of the selection: `tpm::pcr_read` hands this string
/// to `tpm2_pcrread`, and `tpm::parse_pcr_spec` derives the envelope's
/// (alg_id, bitmap) from the same string. Declared selection and attested
/// contents therefore cannot diverge (tactiq-attest#1); there is no separate
/// alg/bitmap constant to keep in sync.
///
/// It is not a constant of the protocol: `verifier-rats` compares the selection
/// against the reference set's `expected_selection` before it compares the
/// composite, so the selection is a property of the platform profile. It is a
/// default here, overridable via TACTIQ_PCR_SPEC, and the value that ends up in
/// the golden set is whatever the device actually sends at enrolment.
const DEFAULT_PCR_SPEC: &str = "sha256:0,1,2,3,4,5,6,7";

const DEFAULT_KEYS_DIR: &str = "/data/tactiq/keys";
const DEFAULT_OUT_DIR: &str = "/data/tactiq/audit";
const DEFAULT_WORK_DIR: &str = "/run/tactiq-agent";
const DEFAULT_INTERVAL_SECS: u64 = 30;
/// Envelopes kept in the audit directory: one day at the default interval.
/// Older ones are removed after each cycle, so the directory is bounded.
const DEFAULT_AUDIT_KEEP: usize = 2880;

/// Low bits of the envelope counter that count envelopes within one epoch.
///
/// counter = (epoch << SEQ_BITS) | seq. 2^24 envelopes is about 16 years at
/// 30 s; when it is reached the agent takes the next epoch. Every value of
/// epoch e is above every value of epoch e-1, so the verifier's strictly-greater
/// rule holds across restarts, and any epoch >= 1 is above every counter the
/// earlier per-cycle scheme issued (those stayed far below 2^24).
const SEQ_BITS: u32 = 24;
const SEQ_LIMIT: u64 = 1 << SEQ_BITS;

/// The envelope counter for `seq` within `epoch`.
fn compose_counter(epoch: u64, seq: u64) -> Result<u64, String> {
    if seq >= SEQ_LIMIT {
        return Err(format!("seq {seq} out of range"));
    }
    if epoch >= 1u64 << (64 - SEQ_BITS) {
        return Err(format!(
            "epoch {epoch} does not fit beside a {SEQ_BITS}-bit seq"
        ));
    }
    Ok((epoch << SEQ_BITS) | seq)
}

/// Hands out envelope counters. One NV increment per epoch, not per envelope.
struct CounterAlloc {
    epoch: Option<u64>,
    next_seq: u64,
}

impl CounterAlloc {
    fn new() -> Self {
        CounterAlloc {
            epoch: None,
            next_seq: 0,
        }
    }

    /// The next counter, taking a new epoch from the TPM when there is none
    /// yet or the current one is used up. The epoch is advanced in NV before
    /// any envelope of it exists; if the process dies after that, the epoch is
    /// simply never used, which the verifier accepts as a gap.
    fn next(&mut self, work: &Path) -> Result<u64, String> {
        if self.epoch.is_none() || self.next_seq >= SEQ_LIMIT {
            tpm::verify_counter()?;
            self.epoch = Some(tpm::nv_increment_and_read(work)?);
            self.next_seq = 0;
        }
        let c = compose_counter(self.epoch.unwrap(), self.next_seq)?;
        self.next_seq += 1;
        Ok(c)
    }
}

/// Stems of envelope files to remove so that at most `keep` remain.
///
/// Only names of the form `<digits>.msg|.attest|.sig|.tag` count; anything
/// else in the directory is left alone. Order is numeric, not lexical, so a
/// stem that outgrows 12 digits still sorts after the shorter ones.
fn stems_to_prune(names: &[String], keep: usize) -> Vec<String> {
    let mut stems: Vec<(u64, String)> = names
        .iter()
        .filter_map(|n| {
            let (stem, ext) = n.rsplit_once('.')?;
            if !matches!(ext, "msg" | "attest" | "sig" | "tag") {
                return None;
            }
            if stem.is_empty() || !stem.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            Some((stem.parse().ok()?, stem.to_string()))
        })
        .collect();
    stems.sort();
    stems.dedup();
    let excess = stems.len().saturating_sub(keep);
    stems.into_iter().take(excess).map(|(_, s)| s).collect()
}

/// Remove the oldest envelopes beyond `keep`. A failure here is returned, not
/// logged and ignored: an agent that cannot bound its directory will fill the
/// data partition, and that should be visible as a failed unit.
fn prune_audit(out: &Path, keep: usize) -> Result<usize, String> {
    let names: Vec<String> = fs::read_dir(out)
        .map_err(|e| format!("read_dir {}: {e}", out.display()))?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    let stems = stems_to_prune(&names, keep);
    for stem in &stems {
        for ext in ["msg", "attest", "sig", "tag"] {
            let p = out.join(format!("{stem}.{ext}"));
            match fs::remove_file(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("remove {}: {e}", p.display())),
            }
        }
    }
    Ok(stems.len())
}

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
        "attest" => {
            cmd_attest(&paths, &work, &out_dir, &pcr_spec, &mut CounterAlloc::new()).map(|_| ())
        }
        "run" => {
            let secs: u64 = env_or("TACTIQ_INTERVAL_SECS", &DEFAULT_INTERVAL_SECS.to_string())
                .parse()
                .unwrap_or(DEFAULT_INTERVAL_SECS);
            let keep: usize = env_or("TACTIQ_AUDIT_KEEP", &DEFAULT_AUDIT_KEEP.to_string())
                .parse()
                .ok()
                .filter(|k| *k > 0)
                .unwrap_or(DEFAULT_AUDIT_KEEP);
            cmd_run(&paths, &work, &out_dir, &pcr_spec, Duration::from_secs(secs), keep)
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
                      TACTIQ_PCR_SPEC TACTIQ_INTERVAL_SECS TACTIQ_AUDIT_KEEP\n\
                      TACTIQ_BOOT_LOG\n\
                   TACTIQ_OWNER_AUTH_FILE TACTIQ_AK_HANDLE TACTIQ_NV_INDEX"
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
            let work = PathBuf::from(env_or("TACTIQ_WORK_DIR", DEFAULT_WORK_DIR));
            ensure_dir(&work)?;
            tpm::verify_ak(&paths.pubkey(), &work)?;
            println!("ak: {} matches {}", tpm::ak_handle()?, paths.pubkey().display());
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

    // An occupied AK handle is never adopted (DDR-005 decision 4). With no
    // recorded public area there is nothing to compare its name with, so the
    // object could be anyone's: a key left by an interrupted run of this
    // agent, or one placed there by something else. Freeing the handle is a
    // deliberate act by the operator, not a repair the agent makes.
    let akh = tpm::ak_handle()?;
    if tpm::handle_exists(&akh)? {
        return Err(format!(
            "{h} already holds an object and this device has no recorded AK; \
             the agent does not adopt a key by its handle. If it is left from an \
             interrupted provisioning, evict it deliberately \
             (tpm2_evictcontrol -C o -c {h}) and provision again",
            h = akh
        ));
    }
    tpm::create_ak(work)?;
    // The counter is kept across agent versions (DDR-005 decision 4): it only
    // ever moves forward, and reusing it costs nothing.
    if !tpm::nv_defined(&tpm::nv_counter()?)? {
        tpm::nv_define()?;
    }

    // Key first, then id. A crash between the two leaves "key, no id", which
    // `inspect` reports as Partial and every command refuses to run on. The
    // reverse order would leave an id with no key, which looks the same from
    // outside but is harder to reason about: the id may already have been
    // handed to the verifier.
    tpm::read_ak_public(&paths.pubkey())?;
    state::finalize_pubkey_perms(paths)?;
    state::sync_dir(&paths.keys_dir)?;
    state::write_id(paths, id)?;

    println!("provisioned {id}");
    println!("  public key: {}", paths.pubkey().display());
    println!("  AK public area (TPM2B_PUBLIC); give it to the verifier as trust/{id}.pub");
    Ok(())
}

/// One attestation cycle. Returns the counter value the envelope carries.
fn cmd_attest(
    paths: &Paths,
    work: &Path,
    out_dir: &str,
    pcr_spec: &str,
    alloc: &mut CounterAlloc,
) -> Result<u64, String> {
    ensure_dir(work)?;
    let out = PathBuf::from(out_dir);
    ensure_dir(&out)?;
    let stale = remove_partials(&out)?;
    if stale > 0 {
        eprintln!(
            "tactiq-agent: removed {stale} file(s) of an envelope whose writing was interrupted"
        );
    }

    let id = match state::inspect(paths) {
        Provisioning::Complete => state::read_id(paths)?,
        Provisioning::Absent => return Err("not provisioned; run `tactiq-agent provision <id>`".into()),
        Provisioning::Partial { have_id, have_key } => {
            return Err(format!(
                "partial provisioning state (device_id: {have_id}, pubkey: {have_key})"
            ))
        }
    };

    // Derive the declared selection from the same spec handed to tpm2_pcrread,
    // and do it before touching the NV counter so a malformed spec cannot burn
    // a counter value on every attempt.
    let (alg_id, bitmap) = tpm::parse_pcr_spec(pcr_spec)?;

    // The AK must be the provisioned one before a counter value is spent on it.
    tpm::verify_ak(&paths.pubkey(), work)?;

    // Order matters: take the counter value before measuring. If the process
    // dies after that, the value is simply never used: a gap in the sequence is
    // harmless because the verifier requires strictly-greater, not consecutive.
    // Measuring first and allocating after would allow two envelopes to
    // describe different states under one counter value.
    let counter = alloc.next(work)?;
    let pcr_state = tpm::pcr_read(pcr_spec, work)?;
    let selection = encode_pcr_selection(alg_id, bitmap);

    let msg = build_canonical(&id, counter, &selection, &pcr_state, &[]);
    if msg.len() != MSG_LEN {
        return Err(format!("built {} bytes, expected {MSG_LEN}", msg.len()));
    }

    let stem = format!("{counter:012}");
    // The tag file is what `custinel-verify` reads to decide the expected
    // disposition; a real emission always expects Accept.
    let tag = format!("{id} counter={counter}\n");
    publish_envelope(&out, &stem, &msg, tag.as_bytes(), |attest, sig| {
        tpm::quote(&msg, pcr_spec, attest, sig)
    })?;

    println!(
        "attested {id} counter={counter} -> {}",
        out.join(format!("{stem}.msg")).display()
    );
    Ok(counter)
}

/// Suffix of the files of an envelope that is still being written. Not one of
/// the envelope extensions, so `stems_to_prune` and every reader ignore them.
const PART: &str = "part";

/// Write `data` to `path` and fsync the file.
fn write_synced(path: &Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut f = fs::File::create(path).map_err(|e| format!("create {}: {e}", path.display()))?;
    f.write_all(data)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    f.sync_all()
        .map_err(|e| format!("fsync {}: {e}", path.display()))
}

/// fsync a file another process wrote (tpm2_quote).
fn sync_file(path: &Path) -> Result<(), String> {
    fs::File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|e| format!("fsync {}: {e}", path.display()))
}

/// Remove the `.part` files of envelopes whose writing was interrupted. They
/// carry no evidence: the envelope was never published under its own name.
fn remove_partials(out: &Path) -> Result<usize, String> {
    let mut n = 0;
    for e in fs::read_dir(out).map_err(|e| format!("read_dir {}: {e}", out.display()))? {
        let e = e.map_err(|e| format!("read_dir {}: {e}", out.display()))?;
        let name = match e.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let is_part = name
            .strip_suffix(&format!(".{PART}"))
            .and_then(|rest| rest.rsplit_once('.'))
            .map(|(stem, ext)| {
                matches!(ext, "msg" | "attest" | "sig" | "tag")
                    && !stem.is_empty()
                    && stem.bytes().all(|b| b.is_ascii_digit())
            })
            .unwrap_or(false);
        if is_part {
            let p = e.path();
            fs::remove_file(&p).map_err(|e| format!("remove {}: {e}", p.display()))?;
            n += 1;
        }
    }
    Ok(n)
}

/// Write one envelope so that a power cut leaves either the whole envelope or
/// no file under the envelope's names.
///
/// Every file is written under a `.part` name and fsynced; then `.msg`,
/// `.attest` and `.sig` are renamed into place, the directory is fsynced, and
/// `.tag` is renamed last and the directory fsynced again. A file under an
/// envelope name is therefore always complete, and an envelope with its `.tag`
/// has all four. A cut between the renames leaves a complete envelope without
/// its tag; a cut before them leaves only `.part` files, removed on the next
/// cycle. `quote` writes the attestation and the signature to the two paths it
/// is given.
fn publish_envelope<F>(
    out: &Path,
    stem: &str,
    msg: &[u8],
    tag: &[u8],
    quote: F,
) -> Result<(), String>
where
    F: FnOnce(&Path, &Path) -> Result<(), String>,
{
    let part = |ext: &str| out.join(format!("{stem}.{ext}.{PART}"));
    let fin = |ext: &str| out.join(format!("{stem}.{ext}"));
    let cleanup = || {
        for ext in ["msg", "attest", "sig", "tag"] {
            let _ = fs::remove_file(part(ext));
        }
    };
    let staged = (|| {
        write_synced(&part("msg"), msg)?;
        quote(&part("attest"), &part("sig"))?;
        sync_file(&part("attest"))?;
        sync_file(&part("sig"))?;
        write_synced(&part("tag"), tag)
    })();
    if let Err(e) = staged {
        cleanup();
        return Err(e);
    }
    for ext in ["msg", "attest", "sig"] {
        fs::rename(part(ext), fin(ext))
            .map_err(|e| format!("rename {}: {e}", fin(ext).display()))?;
    }
    state::sync_dir(out)?;
    fs::rename(part("tag"), fin("tag"))
        .map_err(|e| format!("rename {}: {e}", fin("tag").display()))?;
    state::sync_dir(out)
}

/// Where the kernel publishes the boot event log the loader wrote (TCG2,
/// crypto-agile). On the Rock 5A the device tree names the area
/// (tactiq-os 0005-arm64-dts-rk3588s-rock-5a-expose-tpm-event-log.patch).
const DEFAULT_BOOT_LOG: &str = "/sys/kernel/security/tpm0/binary_bios_measurements";
/// The loader's log area is 64 KiB; anything far larger is not that log.
const BOOT_LOG_MAX: u64 = 1 << 20;

/// Copy the boot event log into the audit directory as
/// `boot-<sha256 of the log>.bios.log`.
///
/// The log is not part of any envelope and the agent does not sign it: it
/// needs no signature of its own. Its SHA-256 bank replays to the PCR values
/// that every quote of the same boot signs, so a verifier holding a quote can
/// check the log against it, and the log of a different boot does not replay.
/// Naming the file by its content makes the save idempotent: a restart of the
/// agent within one boot finds the file in place, and two boots that measured
/// exactly the same chain share one file, which is correct because their logs
/// are identical. No boot identifier is read, so the agent needs no access to
/// kernel sysctls for this.
///
/// Returns the path written, or None when there is nothing to do: the same
/// log is already saved, or the platform publishes none. Failures are
/// reported to the caller, which must not stop attesting because of them.
fn save_boot_log(out: &Path, src: &Path) -> Result<Option<PathBuf>, String> {
    use std::io::Read;
    // A save cut short leaves only a part file; it carries nothing.
    for e in fs::read_dir(out).map_err(|e| format!("read_dir {}: {e}", out.display()))? {
        let e = e.map_err(|e| format!("read_dir {}: {e}", out.display()))?;
        if let Ok(n) = e.file_name().into_string() {
            if n.starts_with("boot-") && n.ends_with(&format!(".bios.log.{PART}")) {
                let p = e.path();
                fs::remove_file(&p).map_err(|e| format!("remove {}: {e}", p.display()))?;
            }
        }
    }
    let f = match fs::File::open(src) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("open {}: {e}", src.display())),
    };
    let mut data = Vec::new();
    f.take(BOOT_LOG_MAX + 1)
        .read_to_end(&mut data)
        .map_err(|e| format!("read {}: {e}", src.display()))?;
    if data.len() as u64 > BOOT_LOG_MAX {
        return Err(format!("{} is larger than {BOOT_LOG_MAX} bytes", src.display()));
    }
    if data.is_empty() {
        return Ok(None);
    }
    // evidence_digest is plain SHA-256 over the bytes; it is reused here so the
    // agent keeps its single dependency.
    let hex: String = attest_envelope::evidence_digest(&data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let name = format!("boot-{hex}.bios.log");
    let dst = out.join(&name);
    if dst.exists() {
        return Ok(None);
    }
    let tmp = out.join(format!("{name}.{PART}"));
    write_synced(&tmp, &data)?;
    fs::rename(&tmp, &dst).map_err(|e| format!("rename {}: {e}", dst.display()))?;
    state::sync_dir(out)?;
    Ok(Some(dst))
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
    keep: usize,
) -> Result<(), String> {
    // Refuse to start at all on a bad identity, rather than starting and
    // failing every cycle.
    match state::inspect(paths) {
        Provisioning::Complete => {}
        other => return Err(format!("cannot run: {other:?}")),
    }

    let mut alloc = CounterAlloc::new();
    let out = PathBuf::from(out_dir);
    ensure_dir(&out)?;
    // Best effort: a missing or unreadable boot log costs the verifier the log
    // route for this boot, not the envelopes, so it never stops the agent.
    let src = PathBuf::from(env_or("TACTIQ_BOOT_LOG", DEFAULT_BOOT_LOG));
    match save_boot_log(&out, &src) {
        Ok(Some(p)) => eprintln!("tactiq-agent: boot event log saved as {}", p.display()),
        Ok(None) => {}
        Err(e) => eprintln!("tactiq-agent: boot event log not saved: {e}"),
    }
    sd_notify("READY=1");
    loop {
        let started = Instant::now();
        match cmd_attest(paths, work, out_dir, pcr_spec, &mut alloc)
            .and_then(|_| prune_audit(&out, keep))
        {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("prover-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn listing(d: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(d)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn publish_writes_all_four_and_no_part_files() {
        let d = tmpdir("publish-ok");
        publish_envelope(&d, "000000000007", b"msg", b"tag\n", |a, s| {
            fs::write(a, b"attest").unwrap();
            fs::write(s, b"sig").unwrap();
            Ok(())
        })
        .unwrap();
        assert_eq!(
            listing(&d),
            vec![
                "000000000007.attest",
                "000000000007.msg",
                "000000000007.sig",
                "000000000007.tag"
            ]
        );
        assert_eq!(fs::read(d.join("000000000007.attest")).unwrap(), b"attest");
        assert_eq!(fs::read(d.join("000000000007.tag")).unwrap(), b"tag\n");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn failed_quote_leaves_no_file_of_the_envelope() {
        let d = tmpdir("publish-fail");
        let r = publish_envelope(&d, "000000000008", b"msg", b"tag\n", |a, _s| {
            fs::write(a, b"half").unwrap();
            Err("tpm2_quote failed".into())
        });
        assert!(r.is_err());
        assert!(listing(&d).is_empty(), "{:?}", listing(&d));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn interrupted_envelope_is_invisible_and_removed_next_cycle() {
        let d = tmpdir("partials");
        // what a power cut during writing leaves: files under .part names,
        // some of them empty
        for n in [
            "000000000009.msg.part",
            "000000000009.attest.part",
            "000000000009.sig.part",
        ] {
            fs::write(d.join(n), b"").unwrap();
        }
        fs::write(d.join("000000000005.msg"), b"m").unwrap();
        fs::write(d.join("notes.part"), b"x").unwrap();
        // the pruner does not see them as envelopes
        assert!(stems_to_prune(&listing(&d), 0) == vec!["000000000005".to_string()]);
        assert_eq!(remove_partials(&d).unwrap(), 3);
        assert_eq!(listing(&d), vec!["000000000005.msg", "notes.part"]);
        fs::remove_dir_all(&d).unwrap();
    }

    /// The default selection must encode to the exact bytes the envelope has
    /// always carried (sha256 = 0x000B, PCRs 0..7 = ff 00 00), so this fix
    /// changes nothing on the wire for a default-configured device and a
    /// verifier pinned to an earlier revision keeps matching.
    #[test]
    fn epochs_order_above_each_other_and_above_the_old_scheme() {
        let last_of_1 = compose_counter(1, SEQ_LIMIT - 1).unwrap();
        let first_of_2 = compose_counter(2, 0).unwrap();
        assert!(first_of_2 > last_of_1);
        // Highest value the per-cycle scheme issued on the bench was 8039.
        assert!(compose_counter(1, 0).unwrap() > 8039);
        assert_eq!(compose_counter(3, 5).unwrap(), (3 << 24) | 5);
    }

    #[test]
    fn counter_parts_out_of_range_are_refused() {
        compose_counter(1, SEQ_LIMIT).unwrap_err();
        compose_counter(1u64 << 40, 0).unwrap_err();
        compose_counter((1u64 << 40) - 1, 0).unwrap();
    }

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn prune_keeps_the_newest_stems() {
        let n = names(&[
            "000000008039.msg",
            "000000008039.sig",
            "000000008039.attest",
            "000000008039.tag",
            "000016777216.msg",
            "000016777216.sig",
            "000016777217.msg",
            "000000000256.msg",
        ]);
        assert_eq!(stems_to_prune(&n, 2), vec!["000000000256", "000000008039"]);
        assert!(stems_to_prune(&n, 4).is_empty());
        assert!(stems_to_prune(&n, 10).is_empty());
    }

    #[test]
    fn prune_ignores_files_that_are_not_envelopes() {
        let n = names(&[
            "idbloader-backup-current.img",
            "uboot-backup-current.img",
            "audit.log",
            "000000000001.msg",
            "000000000002.msg",
            "abc.msg",
            ".msg",
            "000000000003.bin",
        ]);
        assert_eq!(stems_to_prune(&n, 1), vec!["000000000001"]);
    }

    #[test]
    fn prune_order_is_numeric_past_twelve_digits() {
        let n = names(&["999999999999.msg", "1000000000000.msg"]);
        assert_eq!(stems_to_prune(&n, 1), vec!["999999999999"]);
    }

    #[test]
    fn prune_removes_every_file_of_a_stem_and_nothing_else() {
        let d = std::env::temp_dir().join(format!("prune-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        for f in [
            "000000000001.msg",
            "000000000001.attest",
            "000000000001.sig",
            "000000000001.tag",
            "000000000002.msg",
            "000000000002.tag",
            "keep.img",
        ] {
            fs::write(d.join(f), b"x").unwrap();
        }
        assert_eq!(prune_audit(&d, 1).unwrap(), 1);
        let mut left: Vec<String> = fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(
            left,
            vec!["000000000002.msg", "000000000002.tag", "keep.img"]
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn default_spec_encodes_to_historical_selection_bytes() {
        let (alg_id, bitmap) = tpm::parse_pcr_spec(DEFAULT_PCR_SPEC).unwrap();
        assert_eq!(encode_pcr_selection(alg_id, bitmap), [0x00, 0x0B, 0xff, 0x00, 0x00]);
    }

    fn boot_setup(name: &str, log: Option<&[u8]>) -> (PathBuf, PathBuf) {
        let d = tmpdir(name);
        let out = d.join("audit");
        fs::create_dir_all(&out).unwrap();
        let src = d.join("binary_bios_measurements");
        if let Some(b) = log {
            fs::write(&src, b).unwrap();
        }
        (out, src)
    }

    fn boot_name(log: &[u8]) -> String {
        let hex: String = attest_envelope::evidence_digest(log)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("boot-{hex}.bios.log")
    }

    #[test]
    fn boot_log_saved_under_its_digest_once() {
        let (out, src) = boot_setup("bootlog-once", Some(b"log of boot A"));
        let p = save_boot_log(&out, &src).unwrap().expect("first save writes");
        assert_eq!(p.file_name().unwrap().to_str().unwrap(), boot_name(b"log of boot A"));
        assert_eq!(fs::read(&p).unwrap(), b"log of boot A");
        assert!(save_boot_log(&out, &src).unwrap().is_none(), "same log: no second copy");
        fs::write(&src, b"log of boot B").unwrap();
        assert!(save_boot_log(&out, &src).unwrap().is_some(), "other log: new file");
        assert_eq!(listing(&out).len(), 2);
    }

    #[test]
    fn boot_log_absent_or_empty_is_not_an_error() {
        let (out, src) = boot_setup("bootlog-absent", None);
        assert!(save_boot_log(&out, &src).unwrap().is_none());
        fs::write(&src, b"").unwrap();
        assert!(save_boot_log(&out, &src).unwrap().is_none());
        assert!(listing(&out).is_empty(), "{:?}", listing(&out));
    }

    #[test]
    fn boot_log_refuses_oversize() {
        let (out, src) = boot_setup("bootlog-big", Some(&vec![0u8; (BOOT_LOG_MAX + 1) as usize]));
        assert!(save_boot_log(&out, &src).is_err());
        assert!(listing(&out).is_empty(), "{:?}", listing(&out));
    }

    #[test]
    fn boot_log_removes_stale_part_and_leaves_envelopes() {
        let (out, src) = boot_setup("bootlog-part", Some(b"log"));
        let stale = format!("{}.{PART}", boot_name(b"older log"));
        fs::write(out.join(&stale), b"half").unwrap();
        fs::write(out.join("000000000005.msg"), b"m").unwrap();
        save_boot_log(&out, &src).unwrap();
        let names = listing(&out);
        assert!(!names.contains(&stale), "{names:?}");
        assert!(names.contains(&"000000000005.msg".to_string()));
        assert!(names.contains(&boot_name(b"log")));
        // The envelope pruner never touches the boot log.
        assert_eq!(stems_to_prune(&names, 0), vec!["000000000005".to_string()]);
    }
}
