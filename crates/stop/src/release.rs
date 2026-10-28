//! The operator's release: the one thing that lifts a stop.
//!
//! A stop is lifted only by a release the operator signed for this device
//! and for the epoch the counter moves to. Tripping needs nothing: anyone may
//! stop the agent. That is the rule of lockout/tagout: anyone may apply a
//! lock, and only its owner removes it.
//!
//! Why a signed record and not a TPM policy on the counter. Trip and recover
//! are both an increment, so the TPM cannot tell them apart, and a write
//! policy that reads the counter's own parity would have to name the index,
//! whose name contains that policy. A record signed by the operator does not
//! depend on who can write the counter: an even counter without a valid
//! release for its value is still a stop. A deleted and redefined index, a
//! cleared owner hierarchy or extra increments end, at worst, at an epoch with
//! no release, which is stopped.
//!
//! The record, `/data/tactiq/stop/release`, two lines and nothing else:
//!
//! ```text
//! device TACTIQ-BENCH-001
//! epoch 8128
//! ```
//!
//! The epoch is even (a running state), in decimal without leading zeros.
//! `release.sig` next to it is an ECDSA P-256 signature over the exact bytes
//! of the record, DER-encoded, SHA-256: what `openssl dgst -sha256 -sign`
//! writes. The operator signs on their own machine; the private key never
//! comes near the device. The public key is on the dm-verity root
//! (`/usr/share/tactiq/stop-operator.pem`), set at build time from the
//! operator's keyring, like the network permission key of tactiq-netperm.
//!
//! A release names one epoch, and the counter only moves forward, so a
//! release cannot be used twice: once the agent is stopped again, the next
//! running epoch is a different number.

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;

use crate::port::R;

/// Largest record accepted, and largest signature: a P-256 DER signature is
/// at most 72 bytes.
pub const MAX_RECORD: usize = 256;
pub const MAX_SIG: usize = 80;

/// The operator's public key.
pub struct OperatorKey(VerifyingKey);

impl OperatorKey {
    /// From a PEM `PUBLIC KEY` (SubjectPublicKeyInfo), as `openssl ec -pubout`
    /// writes it. Any other curve or key type is refused.
    pub fn from_pem(pem: &str) -> R<Self> {
        VerifyingKey::from_public_key_pem(pem)
            .map(OperatorKey)
            .map_err(|e| format!("operator key: not a P-256 public key ({e})"))
    }

    #[cfg(test)]
    pub fn from_verifying_key(k: VerifyingKey) -> Self {
        OperatorKey(k)
    }
}

/// A release, after parsing. Only `check` produces one that is trusted.
#[derive(Debug, PartialEq, Eq)]
pub struct Release {
    pub device_id: String,
    pub epoch: u64,
}

/// Parse the two lines, strictly: any other byte, line, order or spelling is
/// refused, so the signed bytes have exactly one reading.
pub fn parse(record: &[u8]) -> R<Release> {
    if record.len() > MAX_RECORD {
        return Err(format!("release: {} bytes, more than {MAX_RECORD}", record.len()));
    }
    let text = std::str::from_utf8(record).map_err(|_| "release: not ASCII".to_string())?;
    if !text.is_ascii() || text.contains('\r') {
        return Err("release: not plain ASCII with LF line ends".into());
    }
    let body = text.strip_suffix('\n').ok_or("release: must end with a newline")?;
    let lines: Vec<&str> = body.split('\n').collect();
    let [dev, ep] = lines.as_slice() else {
        return Err(format!("release: {} lines, expected 2 (device, epoch)", lines.len()));
    };
    let device_id = dev
        .strip_prefix("device ")
        .ok_or("release: first line must be `device <id>`")?;
    if device_id.is_empty()
        || device_id.len() > attest_envelope::DEVICE_ID_LEN
        || !device_id.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err("release: not a valid device id".into());
    }
    let n = ep
        .strip_prefix("epoch ")
        .ok_or("release: second line must be `epoch <n>`")?;
    let epoch: u64 = n.parse().map_err(|_| format!("release: epoch {n:?} is not a number"))?;
    if epoch.to_string() != n {
        return Err(format!("release: epoch {n:?} is not written canonically"));
    }
    if !epoch.is_multiple_of(2) {
        return Err(format!("release: epoch {epoch} is odd, a stopped state; a release names a running one"));
    }
    Ok(Release { device_id: device_id.to_string(), epoch })
}

/// Check a release for `device_id` at `epoch`: the signature first, over the
/// exact bytes, then the content. Ok only if all of it holds.
pub fn check(key: &OperatorKey, record: &[u8], sig_der: &[u8], device_id: &str, epoch: u64) -> R<()> {
    if sig_der.len() > MAX_SIG {
        return Err(format!("release: signature of {} bytes, more than {MAX_SIG}", sig_der.len()));
    }
    let sig = Signature::from_der(sig_der).map_err(|_| "release: signature is not DER ECDSA".to_string())?;
    key.0
        .verify(record, &sig)
        .map_err(|_| "release: signature does not verify against the operator key".to_string())?;
    let r = parse(record)?;
    if r.device_id != device_id {
        return Err(format!("release names device {}, this device is {device_id}", r.device_id));
    }
    if r.epoch != epoch {
        return Err(format!("release names epoch {}, the epoch needed is {epoch}", r.epoch));
    }
    Ok(())
}

#[cfg(test)]
pub mod testkey {
    //! A fixed operator key for tests, and a signer for records.
    use super::OperatorKey;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    pub fn signing() -> SigningKey {
        SigningKey::from_bytes(&[0x42u8; 32].into()).unwrap()
    }

    pub fn key() -> OperatorKey {
        OperatorKey::from_verifying_key(*signing().verifying_key())
    }

    pub fn record(device: &str, epoch: u64) -> Vec<u8> {
        format!("device {device}\nepoch {epoch}\n").into_bytes()
    }

    pub fn sign(record: &[u8]) -> Vec<u8> {
        let s: Signature = signing().sign(record);
        s.to_der().as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::testkey::{key, record, sign};
    use super::*;

    #[test]
    fn a_signed_release_for_this_device_and_epoch_passes() {
        let r = record("device-A", 8128);
        check(&key(), &r, &sign(&r), "device-A", 8128).unwrap();
    }

    #[test]
    fn wrong_device_epoch_or_signature_is_refused() {
        let r = record("device-A", 8128);
        let s = sign(&r);
        assert!(check(&key(), &r, &s, "device-B", 8128).is_err(), "another device");
        assert!(check(&key(), &r, &s, "device-A", 8130).is_err(), "a later epoch: no replay");
        assert!(check(&key(), &r, &s, "device-A", 8126).is_err(), "an earlier epoch");
        let mut bad = s.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(check(&key(), &r, &bad, "device-A", 8128).is_err(), "altered signature");
        let other = record("device-A", 8130);
        assert!(check(&key(), &other, &s, "device-A", 8130).is_err(), "signature of another record");
        let stranger = OperatorKey::from_verifying_key(
            *p256::ecdsa::SigningKey::from_bytes(&[0x07u8; 32].into()).unwrap().verifying_key(),
        );
        assert!(check(&stranger, &r, &s, "device-A", 8128).is_err(), "another operator's key");
        assert!(check(&key(), &r, &[], "device-A", 8128).is_err(), "empty signature");
    }

    #[test]
    fn only_one_spelling_of_the_record_parses() {
        assert!(parse(b"device d\nepoch 8128\n").is_ok());
        for bad in [
            &b"device d\nepoch 8128"[..],            // no final newline
            b"device d\r\nepoch 8128\r\n",           // CRLF
            b"epoch 8128\ndevice d\n",               // order
            b"device d\nepoch 8128\nextra 1\n",      // third line
            b"device d\nepoch 08128\n",              // leading zero
            b"device d\nepoch +8128\n",              // sign
            b"device d\nepoch 8129\n",               // odd: a stopped state
            b"device  d\nepoch 8128\n",              // double space
            b"device \nepoch 8128\n",                // empty id
            b"device d\nepoch 8128\n\n",             // trailing empty line
            b"Device d\nepoch 8128\n",               // case
        ] {
            assert!(parse(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn the_pem_key_openssl_writes_is_read_and_others_are_refused() {
        // `openssl ecparam -name prime256v1 -genkey | openssl ec -pubout`
        let pem = include_str!("../testdata/operator.pub.pem");
        OperatorKey::from_pem(pem).unwrap();
        assert!(OperatorKey::from_pem("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n").is_err());
        assert!(OperatorKey::from_pem(include_str!("../testdata/p384.pub.pem")).is_err(), "P-384");
    }

    #[test]
    fn a_signature_openssl_wrote_verifies() {
        // `openssl dgst -sha256 -sign operator.key.pem -out release.sig release`
        let key = OperatorKey::from_pem(include_str!("../testdata/operator.pub.pem")).unwrap();
        let rec = include_bytes!("../testdata/release");
        let sig = include_bytes!("../testdata/release.sig");
        check(&key, rec, sig, "TACTIQ-BENCH-001", 8128).unwrap();
        assert!(check(&key, rec, sig, "TACTIQ-BENCH-001", 8130).is_err());
    }
}
