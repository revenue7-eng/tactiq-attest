//! Check of a stop receipt (`TQSR`, crate `attest-stop`) away from the device.
//!
//! The question a third party asks: is the agent on this device stopped,
//! now, and who says so. A receipt that passes answers it with two TPM
//! signatures under the device's AK:
//!
//!   * a quote over the boot PCRs whose qualifying data commits to the
//!     receipt's message, and through its `evidence_hash` to the bundle with
//!     the stop record, the NV certify and the verifier's nonce;
//!   * an `NV_Certify` of the stop counter, whose qualifying data commits to
//!     the stop record and the same nonce, read by the TPM itself.
//!
//! The nonce in both makes the answer fresh: it can only have been made after
//! the verifier chose the nonce. The quote names the measured build that
//! answered; the certify gives the counter as the TPM holds it.
//!
//! What the answer means, in the order a reader should trust it:
//!
//!   * an odd counter is a stop the TPM itself states: the certified value
//!     is the TPM's, so no software on the device can present an odd counter
//!     as even. That an odd counter refuses every call is the rule of the
//!     measured build the quote names;
//!   * an even counter with `state = stopped` is a stop the stop service
//!     decided: it found no valid operator release for that epoch;
//!   * an even counter with `state = running` is the service's statement that
//!     it found the operator's release for that epoch. The release itself is
//!     not in the receipt, and this check does not see it.
//!
//! Stateless, like gate 1: the caller supplies the AK, the device id, the
//! reference PCR composite and the nonce it sent. Whether the AK belongs to
//! this TPM is AK registration (DDR-005), done before this check.

use attest_envelope::tpm::Quote;
use attest_envelope::{evidence_digest, parse_bundle, AttestationMessage, DEVICE_ID_LEN, PCR_SELECTION_LEN};
use attest_envelope::{TAG_STOP_STATE, TAG_TPM_NV_CERTIFY, TAG_VERIFIER_NONCE};
use attest_stop::{
    certify_qualifying, check_counter_certify, check_nonce, stop_index_name, stop_quote_qualifying, Kind,
    NvCertify, Receipt, State, StopRecord,
};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

use crate::AkKey;

/// What the verifier holds before it looks at the receipt.
pub struct StopTrust<'a> {
    /// The device's attestation key, registered against its EK.
    pub ak: &'a AkKey,
    /// The device id as the receipt's message carries it (zero-padded).
    pub device_id: [u8; DEVICE_ID_LEN],
    /// The PCR selection the stop service quotes (`sha256:0,1,8`).
    pub pcr_selection: [u8; PCR_SELECTION_LEN],
    /// SHA-256 of the reference values of those PCRs, concatenated in
    /// selection order: what the TPM's `pcrDigest` must be for the build the
    /// verifier accepts.
    pub pcr_composite: [u8; 32],
    /// The nonce the verifier sent. `None` checks a receipt without one (a
    /// gateway refusal), which proves what was said but not when.
    pub nonce: Option<&'a [u8]>,
}

/// A receipt that passed. Every field was signed by the TPM under the AK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopFinding {
    pub kind: Kind,
    /// The service's admission state when it answered.
    pub state: State,
    /// The stop counter, as the TPM certified it.
    pub stop_epoch: u64,
    /// SHA-256 of the gateway policy the service enforces.
    pub policy_digest: [u8; 32],
    /// Bound to the verifier's nonce.
    pub fresh: bool,
}

/// Who says the agent is stopped, if anyone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopBasis {
    /// Odd counter: the TPM's own value says stopped.
    Counter,
    /// Even counter, no valid operator release for it: the service says stopped.
    NoRelease,
    /// Even counter, the service found the operator's release: running.
    Running,
}

impl StopFinding {
    pub fn basis(&self) -> StopBasis {
        match (self.stop_epoch % 2 == 1, self.state) {
            (true, _) => StopBasis::Counter,
            (false, State::Stopped) => StopBasis::NoRelease,
            (false, State::Running) => StopBasis::Running,
        }
    }
}

fn verify(vk: &VerifyingKey, signed: &[u8], sig: &[u8], what: &str) -> Result<(), String> {
    // A TPM emits DER through tpm2-tools `-f plain`; accept fixed r||s too.
    let s = Signature::from_der(sig)
        .or_else(|_| Signature::from_slice(sig))
        .map_err(|e| format!("{what}: malformed signature: {e}"))?;
    vk.verify(signed, &s).map_err(|_| format!("{what}: signature does not verify under the AK"))
}

/// Check a receipt. Order as in gate 1: nothing the receipt says is compared
/// before the signature over it has verified.
///
/// 1. parse the container and the 93-byte message;
/// 2. quote: parse, verify under the AK;
/// 3. quote `extraData` = SHA-256("tactiq-stop/quote/v1\0" || msg), so an
///    agent envelope can never pass here;
/// 4. one PCR bank, equal to the message's selection, and `pcrDigest` equal
///    to the message's `pcr_hash`; then both equal to the verifier's own;
/// 5. device id in the message is the expected one;
/// 6. bundle digest equals `evidence_hash`;
/// 7. bundle: exactly one stop record, one NV certify, at most one nonce,
///    nothing else; the record's epoch equals the message counter;
/// 8. NV certify: verify under the AK; qualifying data over this record and
///    nonce, the stop counter's computed name, 8 bytes at offset 0, equal to
///    the epoch;
/// 9. nonce: present and equal when the verifier sent one, absent when not;
///    a nonce-bound receipt must be a status answer;
/// 10. an odd counter reported as running is refused: the service cannot
///     produce it.
pub fn verify_stop_receipt(receipt: &[u8], t: &StopTrust) -> Result<StopFinding, String> {
    let r = Receipt::parse(receipt)?;
    let msg = AttestationMessage::parse(&r.msg)?;
    let vk = t.ak.verifying_key();

    let q = Quote::parse(&r.quote_attest).map_err(|e| format!("quote: {e}"))?;
    verify(vk, &r.quote_attest, &r.quote_sig, "quote")?;
    if q.extra_data != stop_quote_qualifying(&r.msg).as_slice() {
        return Err("quote: not bound to this receipt's message in the stop domain".into());
    }
    let mut banks = q.pcr_banks.iter();
    let (alg, bits) = match (q.pcr_banks.count(), banks.next()) {
        (1, Some(b)) => b,
        (n, _) => return Err(format!("quote: covers {n} PCR banks, want exactly 1")),
    };
    if alg != u16::from_be_bytes([msg.pcr_selection[0], msg.pcr_selection[1]]) || bits != &msg.pcr_selection[2..] {
        return Err("quote: PCR selection differs from the message's".into());
    }
    if q.pcr_digest != msg.pcr_hash.as_slice() {
        return Err("quote: pcrDigest differs from the message's pcr_hash".into());
    }
    if msg.pcr_selection != t.pcr_selection {
        return Err("quote: covers other PCRs than the reference".into());
    }
    if msg.pcr_hash != t.pcr_composite {
        return Err("quote: the boot PCRs are not the reference build's".into());
    }
    if msg.device_id != t.device_id {
        return Err(format!(
            "receipt is from device {}, expected {}",
            attest_envelope::device_id_display(&msg.device_id),
            attest_envelope::device_id_display(&t.device_id)
        ));
    }
    if evidence_digest(&r.bundle) != msg.evidence_hash {
        return Err("bundle: does not hash to the signed evidence_hash".into());
    }

    let sections = parse_bundle(&r.bundle)?;
    let (mut rec, mut cert, mut nonce) = (None, None, None);
    for s in &sections {
        let slot = match s.tag {
            TAG_STOP_STATE => &mut rec,
            TAG_TPM_NV_CERTIFY => &mut cert,
            TAG_VERIFIER_NONCE => &mut nonce,
            other => return Err(format!("bundle: section 0x{other:04x} has no place in a stop receipt")),
        };
        if slot.replace(s.body).is_some() {
            return Err(format!("bundle: section 0x{:04x} twice", s.tag));
        }
    }
    let body = rec.ok_or("bundle: no stop record")?;
    let record = StopRecord::parse(body)?;
    if record.stop_epoch != msg.counter {
        return Err("stop record: epoch differs from the message counter".into());
    }
    let nonce_bytes: &[u8] = match (t.nonce, nonce) {
        (Some(want), Some(got)) => {
            check_nonce(got)?;
            if got != want {
                return Err("nonce: the receipt answers another challenge".into());
            }
            got
        }
        (Some(_), None) => return Err("nonce: the receipt carries none; it is not an answer to this challenge".into()),
        (None, Some(_)) => return Err("nonce: the receipt carries one, but none was given to check it against".into()),
        (None, None) => &[],
    };
    if !nonce_bytes.is_empty() && record.kind != Kind::Status {
        return Err("stop record: a nonce-bound receipt must be a status answer".into());
    }

    let c = NvCertify::parse(cert.ok_or("bundle: no NV certify")?)?;
    verify(vk, &c.attest, &c.sig, "nv certify")?;
    check_counter_certify(&c.attest, &certify_qualifying(body, nonce_bytes), &stop_index_name(), record.stop_epoch)?;

    if record.stop_epoch % 2 == 1 && record.state == State::Running {
        return Err("stop record: odd counter reported as running".into());
    }

    Ok(StopFinding {
        kind: record.kind,
        state: record.state,
        stop_epoch: record.stop_epoch,
        policy_digest: record.policy_digest,
        fresh: !nonce_bytes.is_empty(),
    })
}
