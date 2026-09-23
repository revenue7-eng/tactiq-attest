//! Gate 1: authenticity and evidence binding (DDR-003, decision 7).
//!
//! Stateless given the device key.
//!
//! The output is [`Authenticated`], whose fields are private: the only way to
//! obtain one is to pass this gate. Gate 3 ([`crate::appraise`]) accepts nothing
//! else, so "gate 3 never sees an unbound bundle or an unverified state" holds
//! for every caller, including callers outside this workspace (DDR-003
//! boundary A).

use attest_envelope::{evidence_digest, AttestationMessage, DEVICE_ID_LEN, PCR_HASH_LEN, PCR_SELECTION_LEN};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

use crate::verdict::Reason;

/// Gate 1 failure classes. A strict subset of [`Reason`]; kept separate so a
/// caller mapping into its own taxonomy can match exhaustively.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Gate1Reject {
    /// the message is not the canonical fixed-length layout.
    Malformed,
    /// the key lookup returned no key for this device_id.
    UnknownDevice,
    /// the signature did not decode, or did not verify over the signed area.
    SignatureFail,
    /// the signature verified, but the bundle does not hash to the signed
    /// `evidence_hash`.
    EvidenceBindingFail,
}

impl From<Gate1Reject> for Reason {
    fn from(r: Gate1Reject) -> Reason {
        match r {
            Gate1Reject::Malformed => Reason::Malformed,
            Gate1Reject::UnknownDevice => Reason::UnknownDevice,
            Gate1Reject::SignatureFail => Reason::SignatureFail,
            Gate1Reject::EvidenceBindingFail => Reason::EvidenceBindingFail,
        }
    }
}

/// Why gate 1 refused, with enough context for a diagnostic line.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Gate1Error {
    /// `None` when the message did not parse, so no device_id is known.
    pub device_id: Option<[u8; DEVICE_ID_LEN]>,
    pub reason: Gate1Reject,
    pub detail: String,
}

/// An envelope that passed gate 1. Fields are private and there is no public
/// constructor: holding a value of this type is the proof that the signature
/// verified under the device's key and the bundle is bound to it.
///
/// ```compile_fail
/// // Not constructible outside gate 1.
/// let a = attest_appraise::Authenticated {
///     device_id: [0; 16], counter: 0, pcr_selection: [0; 5],
///     pcr_hash: [0; 32], evidence: Vec::new(),
/// };
/// ```
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Authenticated {
    device_id: [u8; DEVICE_ID_LEN],
    counter: u64,
    pcr_selection: [u8; PCR_SELECTION_LEN],
    pcr_hash: [u8; PCR_HASH_LEN],
    evidence: Vec<u8>,
}

impl Authenticated {
    pub fn device_id(&self) -> &[u8; DEVICE_ID_LEN] { &self.device_id }
    /// The counter from the signed area, as signed. This crate does not
    /// interpret it.
    pub fn counter(&self) -> u64 { self.counter }
    pub fn pcr_selection(&self) -> &[u8; PCR_SELECTION_LEN] { &self.pcr_selection }
    pub fn pcr_hash(&self) -> &[u8; PCR_HASH_LEN] { &self.pcr_hash }
    /// The bundle, verbatim, verified to hash to the signed `evidence_hash`.
    pub fn evidence(&self) -> &[u8] { &self.evidence }
}

/// Run gate 1 over one envelope.
///
/// Order, each step load-bearing:
/// 1. parse the fixed layout (device_id is read from the signed area);
/// 2. `key_for(device_id)`; `None` refuses as `UnknownDevice`;
/// 3. verify ECDSA P-256 over SHA-256 of the message (DER or raw r||s accepted);
/// 4. only then compare the bundle digest with the signed `evidence_hash`.
///    Before step 3 holds, `evidence_hash` is attacker-chosen and the comparison
///    would prove nothing (DDR-002, decision 5 boundary D).
///
/// Taking a lookup rather than a key keeps parsing inside this function, so the
/// fields in [`Authenticated`] always come from the very bytes that were verified.
pub fn authenticate<F>(
    msg_bytes: &[u8],
    sig_bytes: &[u8],
    evidence: &[u8],
    key_for: F,
) -> Result<Authenticated, Gate1Error>
where
    F: FnOnce(&[u8; DEVICE_ID_LEN]) -> Option<VerifyingKey>,
{
    let msg = AttestationMessage::parse(msg_bytes).map_err(|e| Gate1Error {
        device_id: None,
        reason: Gate1Reject::Malformed,
        detail: e,
    })?;
    let refuse = |reason, detail: String| Gate1Error { device_id: Some(msg.device_id), reason, detail };

    let vk = key_for(&msg.device_id).ok_or_else(|| {
        refuse(Gate1Reject::UnknownDevice, "unknown device (not in trust store)".into())
    })?;

    // DER (variable) or fixed r||s (64 bytes): a TPM emits DER; accept either.
    let sig = Signature::from_der(sig_bytes)
        .or_else(|_| Signature::from_slice(sig_bytes))
        .map_err(|e| refuse(Gate1Reject::SignatureFail, format!("malformed signature: {e}")))?;
    // ECDSA over SHA-256(msg), matching `tpm2_sign -g sha256`.
    if vk.verify(msg_bytes, &sig).is_err() {
        return Err(refuse(Gate1Reject::SignatureFail, "signature verification failed".into()));
    }
    if evidence_digest(evidence) != msg.evidence_hash {
        return Err(refuse(
            Gate1Reject::EvidenceBindingFail,
            format!(
                "evidence binding: bundle of {} byte(s) does not hash to the signed digest",
                evidence.len()
            ),
        ));
    }

    Ok(Authenticated {
        device_id: msg.device_id,
        counter: msg.counter,
        pcr_selection: msg.pcr_selection,
        pcr_hash: msg.pcr_hash,
        evidence: evidence.to_vec(),
    })
}
