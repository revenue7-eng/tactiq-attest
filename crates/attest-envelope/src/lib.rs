//! attest-envelope — the canonical attestation envelope, and nothing else.
//!
//! ```text
//! device_id(16) || counter_be(8) || pcr_selection(5) || pcr_hash(32)   = 61 bytes
//! ```
//!
//! Why this is its own crate
//! -------------------------
//! The envelope has to exist on both sides of the protocol: the prover builds
//! it, the verifier parses it. Everything else in `attest-core` — the trust
//! store, the high-water mark, the durable write — runs only in the appliance.
//!
//! Those two halves have different disclosure profiles. The prover ships on
//! every customer device, so the wire format is recoverable from the binary or
//! from the wire regardless of what the repository says; treating it as secret
//! buys nothing. The verifier does not ship, and can stay closed. Splitting the
//! crate along that line lets the device-side build be reproducible from
//! sources an auditor can obtain, which is what `LAYERS.lock` in tactiq-os
//! claims of every other build input, without opening the verifier.
//!
//! The split costs nothing in safety: prover and verifier still share one
//! codec, byte for byte, because it is literally the same crate. A duplicated
//! codec is the failure this arrangement exists to prevent — the earlier
//! documents described this envelope as `device_id + counter + pcr_hash +
//! timestamp` signed with Ed25519, and neither half was true of the code.
//!
//! This crate holds no state, performs no I/O, and makes no trust decision. It
//! is pure serialisation over bytes.

use sha2::{Digest, Sha256};

pub const DEVICE_ID_LEN: usize = 16;
pub const PCR_HASH_LEN: usize = 32;
pub const COUNTER_LEN: usize = 8;

/// PCR-selection, canonical opaque encoding (mirrors TPMS_PCR_SELECTION):
///   alg_id (u16, big-endian) || pcr_bitmap (3 bytes, TPM bit order: PCR n -> byte n/8, bit n%8)
/// e.g. sha256 over PCRs 0..7  =>  00 0B FF 00 00.
///
/// Nothing here interprets these bytes. They are covered by the signature
/// (gate 1) and handed downstream opaque. Interpretation — comparison against
/// the reference set's expected selection, BEFORE the digest, boundary A of
/// DDR-001 — belongs to gate 3 in verifier-rats.
pub const PCR_SELECTION_LEN: usize = 5;

/// Canonical signed message = device_id(16) || counter_be(8) || pcr_selection(5) || pcr_hash(32)
pub const MSG_LEN: usize = DEVICE_ID_LEN + COUNTER_LEN + PCR_SELECTION_LEN + PCR_HASH_LEN;

#[derive(Debug, Clone)]
pub struct AttestationMessage {
    pub device_id: [u8; DEVICE_ID_LEN],
    pub counter: u64,
    pub pcr_selection: [u8; PCR_SELECTION_LEN],
    pub pcr_hash: [u8; PCR_HASH_LEN],
}

impl AttestationMessage {
    /// Parse the canonical signed bytes. device_id and counter are read FROM the
    /// signed region, so they cannot be altered without breaking the signature.
    ///
    /// The length check is exact, not a minimum: a fixed layout is what keeps
    /// this parser small enough to read in one sitting, which for code inside
    /// the TCB is worth more than extensibility.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != MSG_LEN {
            return Err(format!("bad message length: {} (want {})", bytes.len(), MSG_LEN));
        }
        let mut device_id = [0u8; DEVICE_ID_LEN];
        device_id.copy_from_slice(&bytes[0..DEVICE_ID_LEN]);
        let mut ctr = [0u8; COUNTER_LEN];
        ctr.copy_from_slice(&bytes[DEVICE_ID_LEN..DEVICE_ID_LEN + COUNTER_LEN]);
        let counter = u64::from_be_bytes(ctr); // TPM NV counter is big-endian
        let sel_off = DEVICE_ID_LEN + COUNTER_LEN;
        let mut pcr_selection = [0u8; PCR_SELECTION_LEN];
        pcr_selection.copy_from_slice(&bytes[sel_off..sel_off + PCR_SELECTION_LEN]);
        let mut pcr_hash = [0u8; PCR_HASH_LEN];
        pcr_hash.copy_from_slice(&bytes[sel_off + PCR_SELECTION_LEN..]);
        Ok(Self { device_id, counter, pcr_selection, pcr_hash })
    }

    pub fn device_id_str(&self) -> String {
        device_id_display(&self.device_id)
    }
}

/// The payload gate 3 appraises, extracted from an already signature-verified
/// message. Every field rode inside the signed area, so none can be altered
/// without breaking gate 1. Deliberately minimal: `counter` is NOT here —
/// freshness is fully adjudicated by gate 2 upstream, and carrying it would
/// pre-design for downstream consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedMessage {
    pub device_id: [u8; DEVICE_ID_LEN],
    pub pcr_selection: [u8; PCR_SELECTION_LEN],
    pub pcr_hash: [u8; PCR_HASH_LEN],
}

/// Render a device_id as a trimmed display string (drops NUL padding).
pub fn device_id_display(id: &[u8; DEVICE_ID_LEN]) -> String {
    String::from_utf8_lossy(id)
        .trim_end_matches('\0')
        .trim_end()
        .to_string()
}

/// Hex form of a device_id, used for on-disk filenames by the verifier's
/// durable store. Kept here with its inverse so the two cannot drift.
pub fn id_to_hex(id: &[u8; DEVICE_ID_LEN]) -> String {
    hex::encode(id)
}

pub fn hex_to_id(s: &str) -> Option<[u8; DEVICE_ID_LEN]> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != DEVICE_ID_LEN { return None; }
    let mut id = [0u8; DEVICE_ID_LEN];
    id.copy_from_slice(&bytes);
    Some(id)
}

/// Encode the canonical opaque PCR-selection bytes on the prover side.
/// `alg_id` is the TPM algorithm id (sha256 = 0x000B), `bitmap` is the 3-byte
/// TPM PCR bitmap.
pub fn encode_pcr_selection(alg_id: u16, bitmap: [u8; 3]) -> [u8; PCR_SELECTION_LEN] {
    let a = alg_id.to_be_bytes();
    [a[0], a[1], bitmap[0], bitmap[1], bitmap[2]]
}

/// Build the canonical message. `pcr_state` is the raw selected-PCR contents;
/// the composite digest is taken here rather than by the caller, so prover and
/// verifier agree on the composite by construction instead of by convention.
pub fn build_canonical(
    device_id: &str,
    counter: u64,
    pcr_selection: &[u8; PCR_SELECTION_LEN],
    pcr_state: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(MSG_LEN);
    let mut id = [0u8; DEVICE_ID_LEN];
    let b = device_id.as_bytes();
    id[..b.len().min(DEVICE_ID_LEN)].copy_from_slice(&b[..b.len().min(DEVICE_ID_LEN)]);
    out.extend_from_slice(&id);
    out.extend_from_slice(&counter.to_be_bytes());
    out.extend_from_slice(pcr_selection);
    let pcr_hash = Sha256::digest(pcr_state);
    out.extend_from_slice(&pcr_hash);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sel_sha256_0_7() -> [u8; PCR_SELECTION_LEN] {
        encode_pcr_selection(0x000B, [0xFF, 0x00, 0x00])
    }

    #[test]
    fn message_roundtrip() {
        let sel = sel_sha256_0_7();
        let m = build_canonical("device-A", 42, &sel, b"pcr-state");
        assert_eq!(m.len(), MSG_LEN);
        let parsed = AttestationMessage::parse(&m).unwrap();
        assert_eq!(parsed.counter, 42);
        assert_eq!(parsed.device_id_str(), "device-A");
        assert_eq!(parsed.pcr_selection, sel);
    }

    #[test]
    fn length_is_exact_not_minimum() {
        let sel = sel_sha256_0_7();
        let mut m = build_canonical("device-A", 1, &sel, b"x");
        assert!(AttestationMessage::parse(&m).is_ok());
        m.push(0);
        assert!(AttestationMessage::parse(&m).is_err());
        m.truncate(MSG_LEN - 1);
        assert!(AttestationMessage::parse(&m).is_err());
    }

    #[test]
    fn id_hex_roundtrip() {
        let id = *b"device-A\0\0\0\0\0\0\0\0";
        assert_eq!(hex_to_id(&id_to_hex(&id)), Some(id));
        assert_eq!(hex_to_id("nothex"), None);
        assert_eq!(hex_to_id("00"), None); // wrong width
    }
}
