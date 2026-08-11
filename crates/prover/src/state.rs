//! On-disk identity: the device id and the attestation public key.
//!
//! Where this lives, and why not in the image
//! ------------------------------------------
//! `agent.yaml` ships in the read-only rootfs at `/etc/tactiq/agent.yaml`, and
//! the same image is flashed to every unit. An identity carried there would be
//! identical fleet-wide, which is not an identity. Making it per-unit would mean
//! rebuilding the image per device, which breaks both reproducible builds and
//! shipping one A/B bundle to a fleet.
//!
//! `/data/tactiq/keys` is the persistent partition, per-device, and survives A/B
//! updates. The recipe already creates it 0700 owned by `tactiq-agent`. The
//! identity belongs next to the key because it *is* part of the key material:
//! the verifier's trust store is a map from device id to public key, and the two
//! are provisioned as one pair.
//!
//! The partial-state rule
//! ----------------------
//! Because id and key are provisioned as a pair, they must live and die as a
//! pair. If the id survived and the key were regenerated, the verifier would
//! check a fresh signature against the stale public key it holds under that id
//! and return `SignatureFail` — the reason reserved for forgery. A routine
//! provisioning desync would then be indistinguishable from an attack, which is
//! exactly the distinction `verifier-rats` keeps a separate reason for.
//!
//! So: both present, proceed. Neither present, provision. Exactly one present,
//! fail closed and do not self-repair.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use attest_envelope::DEVICE_ID_LEN;

pub type R<T> = Result<T, String>;

pub struct Paths {
    pub keys_dir: PathBuf,
}

impl Paths {
    pub fn new(keys_dir: impl Into<PathBuf>) -> Self {
        Self { keys_dir: keys_dir.into() }
    }
    pub fn device_id(&self) -> PathBuf { self.keys_dir.join("device_id") }
    pub fn pubkey(&self) -> PathBuf { self.keys_dir.join("pubkey.pem") }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Provisioning {
    /// Both id and public key are present: the device has an identity.
    Complete,
    /// Neither is present: a first boot, safe to provision.
    Absent,
    /// Exactly one is present. Never repaired automatically.
    Partial { have_id: bool, have_key: bool },
}

pub fn inspect(p: &Paths) -> Provisioning {
    let have_id = p.device_id().exists();
    let have_key = p.pubkey().exists();
    match (have_id, have_key) {
        (true, true) => Provisioning::Complete,
        (false, false) => Provisioning::Absent,
        _ => Provisioning::Partial { have_id, have_key },
    }
}

/// A device id is a short printable string, zero-padded into the envelope's
/// 16-byte field by `attest-core`. It is not derived from hardware: the same
/// string has to be handed to the verifier alongside the public key, so it is
/// assigned at provisioning, exactly as `run.sh` assigns `device-A`.
pub fn validate_id(id: &str) -> R<()> {
    if id.is_empty() {
        return Err("device id is empty".into());
    }
    if id.len() > DEVICE_ID_LEN {
        return Err(format!("device id {:?} is {} bytes, max {DEVICE_ID_LEN}", id, id.len()));
    }
    if !id.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!("device id {:?} must be printable ASCII without spaces", id));
    }
    Ok(())
}

pub fn read_id(p: &Paths) -> R<String> {
    let raw = fs::read_to_string(p.device_id())
        .map_err(|e| format!("read {}: {e}", p.device_id().display()))?;
    let id = raw.trim().to_string();
    validate_id(&id)?;
    Ok(id)
}

/// Write the device id 0600. Called only after the key exists, so that a crash
/// between the two steps leaves the "no id, key present" partial state — which
/// `inspect` reports and the caller refuses to run on, rather than a device that
/// looks provisioned but is not.
pub fn write_id(p: &Paths, id: &str) -> R<()> {
    validate_id(id)?;
    let path = p.device_id();
    let mut f = fs::OpenOptions::new()
        .write(true).create_new(true).mode(0o600)
        .open(&path)
        .map_err(|e| format!("create {}: {e}", path.display()))?;
    writeln!(f, "{id}").map_err(|e| format!("write {}: {e}", path.display()))?;
    f.sync_all().map_err(|e| format!("fsync {}: {e}", path.display()))?;
    sync_dir(&p.keys_dir)
}

/// The public key is not secret — the verifier needs it — but the directory it
/// sits in is 0700, so 0644 here only matters if the file is ever copied out.
pub fn finalize_pubkey_perms(p: &Paths) -> R<()> {
    let path = p.pubkey();
    let mut perm = fs::metadata(&path)
        .map_err(|e| format!("stat {}: {e}", path.display()))?
        .permissions();
    perm.set_mode(0o644);
    fs::set_permissions(&path, perm)
        .map_err(|e| format!("chmod {}: {e}", path.display()))
}

/// fsync the directory so the rename/create is durable, not just the file
/// contents. Same discipline as the verifier's write-ahead high-water mark.
pub fn sync_dir(dir: &Path) -> R<()> {
    fs::File::open(dir)
        .and_then(|f| f.sync_all())
        .map_err(|e| format!("fsync dir {}: {e}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_must_fit_the_envelope_field() {
        assert!(validate_id("device-A").is_ok());
        assert!(validate_id("0123456789abcdef").is_ok()); // exactly 16
        assert!(validate_id("0123456789abcdefg").is_err()); // 17
        assert!(validate_id("").is_err());
        assert!(validate_id("has space").is_err());
    }

    #[test]
    fn partial_state_is_reported_not_repaired() {
        let d = std::env::temp_dir().join(format!("prover-state-{}", std::process::id()));
        let _ = fs::create_dir_all(&d);
        let p = Paths::new(&d);
        assert_eq!(inspect(&p), Provisioning::Absent);

        fs::write(p.device_id(), "device-A\n").unwrap();
        assert_eq!(inspect(&p), Provisioning::Partial { have_id: true, have_key: false });

        fs::write(p.pubkey(), "-----BEGIN PUBLIC KEY-----\n").unwrap();
        assert_eq!(inspect(&p), Provisioning::Complete);

        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn id_is_not_overwritten_once_written() {
        let d = std::env::temp_dir().join(format!("prover-id-{}", std::process::id()));
        let _ = fs::create_dir_all(&d);
        let p = Paths::new(&d);
        write_id(&p, "device-A").unwrap();
        // create_new: a second provisioning attempt must not silently rebrand
        // a device that the verifier already knows under the first id.
        assert!(write_id(&p, "device-B").is_err());
        assert_eq!(read_id(&p).unwrap(), "device-A");
        let _ = fs::remove_dir_all(&d);
    }
}
