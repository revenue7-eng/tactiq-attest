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
    certify_qualifying, check_counter_certify, check_nonce, parse_nv_certify_info, stop_index_name,
    stop_quote_qualifying, Kind, NvCertify, Receipt, State, StopRecord, TpmClock,
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
    /// When the TPM read the stop counter, by its own clock (the certify's
    /// `clockInfo`). The quote of the same receipt was made in the same TPM
    /// boot: the check refuses a receipt whose two signatures come from two.
    pub clock: TpmClock,
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
///     produce it;
/// 11. the certify and the quote were made in one TPM boot (equal
///     `resetCount` and `restartCount`), so the counter that was read and
///     the build that was quoted are of the same boot.
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
    let clock = parse_nv_certify_info(&c.attest)?.clock;
    let qc = &q.clock_info;
    let quoted = TpmClock { clock: qc.clock, reset_count: qc.reset_count, restart_count: qc.restart_count, safe: qc.safe };
    if !clock.same_boot(&quoted) {
        return Err(format!(
            "receipt: the counter was read in one TPM boot (reset {}, restart {}) and the build quoted in another \
             (reset {}, restart {})",
            clock.reset_count, clock.restart_count, quoted.reset_count, quoted.restart_count
        ));
    }

    Ok(StopFinding {
        kind: record.kind,
        state: record.state,
        stop_epoch: record.stop_epoch,
        policy_digest: record.policy_digest,
        fresh: !nonce_bytes.is_empty(),
        clock,
    })
}

/// A stop that held between two receipts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopInterval {
    /// The odd stop counter, equal at both ends.
    pub stop_epoch: u64,
    /// The TPM's clock when it read the counter, at each end.
    pub from: TpmClock,
    pub to: TpmClock,
}

impl StopInterval {
    /// Milliseconds of TPM clock between the two reads.
    pub fn held_ms(&self) -> u64 {
        self.to.clock - self.from.clock
    }
}

/// Check that the stop held from one receipt to a later one, with nothing
/// from the device but the two receipts and the AK.
///
/// Each receipt must pass [`verify_stop_receipt`] against the same AK, device
/// and reference build, each with its own nonce (`t.nonce` must be `None`;
/// the nonces are given here). Then:
///
/// 1. the two nonces differ;
/// 2. both counters are odd: a stop the TPM itself states. An even counter
///    with no release is the service's word and is refused here;
/// 3. the counter is the same at both ends. The TPM only ever increments it,
///    and both a lift and a new trip increment it, so an equal value means
///    neither happened in between. A counter deleted and defined again
///    starts above every value the chip has held, so it cannot come back to
///    this one;
/// 4. the same TPM boot at both ends: equal `resetCount` (no reboot) and
///    equal `restartCount` (no resume). Within one boot PCRs only move
///    forward by extend, so both quotes equal to the reference means the
///    reference build ran the whole time;
/// 5. the second read is later by the TPM clock.
///
/// Not established: anything about wall time (the TPM clock counts while
/// powered and can be moved forward by its owner or platform, so
/// [`StopInterval::held_ms`] can be more than the time that passed, never
/// less within one boot); and that no command reached a process while the
/// gateway refused: that needs an observation of the process itself.
pub fn verify_stop_interval(
    first: &[u8],
    first_nonce: &[u8],
    second: &[u8],
    second_nonce: &[u8],
    t: &StopTrust,
) -> Result<StopInterval, String> {
    if t.nonce.is_some() {
        return Err("interval: give the nonces to verify_stop_interval, not in the trust".into());
    }
    if first_nonce == second_nonce {
        return Err("interval: both receipts answer the same challenge".into());
    }
    let at = |r: &[u8], n: &[u8], which: &str| {
        let tn = StopTrust { nonce: Some(n), ..*t };
        verify_stop_receipt(r, &tn).map_err(|e| format!("{which} receipt: {e}"))
    };
    let a = at(first, first_nonce, "first")?;
    let b = at(second, second_nonce, "second")?;
    for (f, which) in [(&a, "first"), (&b, "second")] {
        if f.basis() != StopBasis::Counter {
            return Err(format!(
                "interval: the {which} receipt is not a stop the TPM states (counter {} is even)",
                f.stop_epoch
            ));
        }
    }
    if a.stop_epoch != b.stop_epoch {
        return Err(format!(
            "interval: the stop counter moved from {} to {}: the stop was lifted or tripped again in between",
            a.stop_epoch, b.stop_epoch
        ));
    }
    if a.clock.reset_count != b.clock.reset_count {
        return Err(format!(
            "interval: the TPM was reset in between (resetCount {} then {}): a reboot, after which any build may have run",
            a.clock.reset_count, b.clock.reset_count
        ));
    }
    if a.clock.restart_count != b.clock.restart_count {
        return Err(format!(
            "interval: the TPM was restarted in between (restartCount {} then {})",
            a.clock.restart_count, b.clock.restart_count
        ));
    }
    if b.clock.clock <= a.clock.clock {
        return Err(format!(
            "interval: the second receipt is not later by the TPM clock ({} then {} ms)",
            a.clock.clock, b.clock.clock
        ));
    }
    Ok(StopInterval { stop_epoch: a.stop_epoch, from: a.clock, to: b.clock })
}
