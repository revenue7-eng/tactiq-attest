//! The decisions of the stop service, with no I/O of their own: what the
//! state is, whether a call passes, how a signed answer is assembled, and
//! what trip and recover do. Everything here runs against `StopTpm`.

use attest_envelope::{
    build_bundle, build_canonical, encode_pcr_selection, MSG_LEN, TAG_STOP_STATE,
    TAG_TPM_NV_CERTIFY, TAG_VERIFIER_NONCE,
};
use attest_stop::{
    certify_qualifying, check_counter_certify, check_nonce, stop_quote_qualifying, Kind,
    NvCertify, Receipt, State, StopRecord,
};

use crate::port::{StopTpm, R};

/// The stop state is the parity of the stop counter: odd = stopped. Trip and
/// recover each advance it by one, so the state changes only by an increment.
///
/// What this does not protect against, in this version: anyone who can write
/// the index (the owner hierarchy, whose auth is empty on TactiQ OS) can
/// advance it, and the owner can delete and redefine it. Closing that needs
/// an operator policy on the index and is a separate step.
pub fn state_of(counter: u64) -> State {
    if counter.is_multiple_of(2) {
        State::Running
    } else {
        State::Stopped
    }
}

/// Fixed context of one service instance.
pub struct Ctx<'a> {
    pub device_id: &'a str,
    pub pcr_spec: &'a str,
    pub pcr_alg: u16,
    pub pcr_bitmap: [u8; 3],
    pub policy_digest: [u8; 32],
    /// TPM name of the stop counter, read at start. A certify that names any
    /// other index is refused before a receipt leaves the service.
    pub stop_index_name: &'a [u8],
}

/// What the gateway gets for one call.
#[derive(Debug, PartialEq, Eq)]
pub enum Admission {
    /// Running: let the call through.
    Allow,
    /// Stopped: refuse, with a signed receipt as the body.
    Refuse(Vec<u8>),
}

/// Decide one call. Any error is the caller's to turn into a refusal: the
/// service never lets a call through because it could not read the state.
pub fn admit(tpm: &dyn StopTpm, ctx: &Ctx, request_digest: [u8; 32]) -> R<Admission> {
    let counter = tpm.read_counter()?;
    match state_of(counter) {
        State::Running => Ok(Admission::Allow),
        State::Stopped => {
            let rec = StopRecord {
                kind: Kind::Refusal { request_digest },
                state: State::Stopped,
                stop_epoch: counter,
                policy_digest: ctx.policy_digest,
            };
            Ok(Admission::Refuse(sign(tpm, ctx, &rec, &[])?))
        }
    }
}

/// A signed answer to "what is the state now", optionally bound to a
/// verifier's nonce.
pub fn status(tpm: &dyn StopTpm, ctx: &Ctx, nonce: &[u8]) -> R<Vec<u8>> {
    if !nonce.is_empty() {
        check_nonce(nonce)?;
    }
    let counter = tpm.read_counter()?;
    let rec = StopRecord {
        kind: Kind::Status,
        state: state_of(counter),
        stop_epoch: counter,
        policy_digest: ctx.policy_digest,
    };
    sign(tpm, ctx, &rec, nonce)
}

/// Assemble and sign a receipt for `rec`.
///
/// 1. The TPM certifies the stop counter, with qualifying data bound to this
///    record and nonce.
/// 2. The service parses that certify and refuses to go on unless it names
///    the stop counter, covers its 8 bytes from offset 0, carries this
///    qualifying data, and reads exactly `stop_epoch`. A counter that moved
///    between the service's read and the TPM's is caught here, on the
///    device, and the call is denied without a receipt.
/// 3. Record, certify and nonce go into the bundle; its digest goes into the
///    93-byte message.
/// 4. The TPM quotes the PCRs with qualifying data
///    SHA-256("tactiq-stop/quote/v1\0" || message), a domain an agent
///    envelope never uses.
fn sign(tpm: &dyn StopTpm, ctx: &Ctx, rec: &StopRecord, nonce: &[u8]) -> R<Vec<u8>> {
    let body = rec.encode()?;
    let qd = certify_qualifying(&body, nonce);
    let (c_attest, c_sig) = tpm.certify(&qd)?;
    check_counter_certify(&c_attest, &qd, ctx.stop_index_name, rec.stop_epoch)?;
    let cert = NvCertify { attest: c_attest, sig: c_sig }.encode()?;

    let mut sections: Vec<(u16, &[u8])> = vec![(TAG_STOP_STATE, &body), (TAG_TPM_NV_CERTIFY, &cert)];
    if !nonce.is_empty() {
        sections.push((TAG_VERIFIER_NONCE, nonce));
    }
    let bundle = build_bundle(&sections)?;

    let pcr_state = tpm.pcr_read(ctx.pcr_spec)?;
    let selection = encode_pcr_selection(ctx.pcr_alg, ctx.pcr_bitmap);
    // The message counter carries the stop epoch. The quote's own qualifying
    // domain keeps these envelopes out of any agent-envelope verifier.
    let msg = build_canonical(ctx.device_id, rec.stop_epoch, &selection, &pcr_state, &bundle);
    if msg.len() != MSG_LEN {
        return Err(format!("built {} bytes, expected {MSG_LEN}", msg.len()));
    }
    let (q_attest, q_sig) = tpm.quote(&stop_quote_qualifying(&msg), ctx.pcr_spec)?;
    Receipt { msg, quote_attest: q_attest, quote_sig: q_sig, bundle }.encode()
}

/// What an operator command did.
#[derive(Debug, PartialEq, Eq)]
pub enum Transition {
    Changed { from: u64, to: u64 },
    AlreadyThere { at: u64 },
}

/// An operator command that failed, with the state as last known, so the
/// operator is never left guessing whether the agent is stopped.
#[derive(Debug, PartialEq, Eq)]
pub struct TransitionError {
    pub message: String,
    /// The counter as read after the failure, if it could be read.
    pub now: Option<u64>,
}

/// Stop the agent. Idempotent: on an already odd counter it does nothing, so
/// a repeated trip cannot flip the state back to running. Callers hold the
/// admin lock so two operator commands cannot interleave their read and
/// increment.
pub fn trip(tpm: &dyn StopTpm) -> Result<Transition, TransitionError> {
    move_to(tpm, State::Stopped)
}

/// Lift a stop. Idempotent in the same way.
pub fn recover(tpm: &dyn StopTpm) -> Result<Transition, TransitionError> {
    move_to(tpm, State::Running)
}

/// Bring a freshly defined counter to the wanted state. Same rule: at most
/// one increment, and only if the parity is wrong.
pub fn settle(tpm: &dyn StopTpm, want: State) -> Result<Transition, TransitionError> {
    move_to(tpm, want)
}

fn move_to(tpm: &dyn StopTpm, want: State) -> Result<Transition, TransitionError> {
    let fail = |message: String| TransitionError { message, now: tpm.read_counter().ok() };
    let from = tpm.read_counter().map_err(|e| TransitionError { message: e, now: None })?;
    if state_of(from) == want {
        return Ok(Transition::AlreadyThere { at: from });
    }
    if let Err(e) = tpm.increment() {
        return Err(fail(format!("increment failed: {e}")));
    }
    let to = match tpm.read_counter() {
        Ok(v) => v,
        Err(e) => return Err(fail(format!("increment sent, but the counter could not be read back: {e}"))),
    };
    if to != from + 1 {
        return Err(TransitionError {
            message: format!(
                "the counter went from {from} to {to}, not {}: another writer moved it",
                from + 1
            ),
            now: Some(to),
        });
    }
    Ok(Transition::Changed { from, to })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::port::fake::{Fake, INDEX_NAME};
    use attest_envelope::{parse_bundle, AttestationMessage};

    fn ctx() -> Ctx<'static> {
        Ctx {
            device_id: "device-A",
            pcr_spec: "sha256:0,1,8",
            pcr_alg: 0x000B,
            pcr_bitmap: [0x03, 0x01, 0x00],
            policy_digest: [0x11; 32],
            stop_index_name: &INDEX_NAME,
        }
    }

    fn sections_of(receipt: &[u8]) -> (Receipt, Vec<(u16, Vec<u8>)>) {
        let r = Receipt::parse(receipt).unwrap();
        let s = parse_bundle(&r.bundle)
            .unwrap()
            .into_iter()
            .map(|s| (s.tag, s.body.to_vec()))
            .collect();
        (r, s)
    }

    #[test]
    fn parity_is_the_state() {
        assert_eq!(state_of(0), State::Running);
        assert_eq!(state_of(1), State::Stopped);
        assert_eq!(state_of(2), State::Running);
        assert_eq!(state_of(u64::MAX), State::Stopped);
    }

    #[test]
    fn running_lets_the_call_through_without_signing() {
        let t = Fake::at(4);
        assert_eq!(admit(&t, &ctx(), [0; 32]).unwrap(), Admission::Allow);
        assert!(t.quoted.borrow().is_empty() && t.certified.borrow().is_empty());
    }

    #[test]
    fn stopped_refuses_with_a_receipt_naming_the_call() {
        let t = Fake::at(5);
        let Admission::Refuse(b) = admit(&t, &ctx(), [0x22; 32]).unwrap() else {
            panic!("expected a refusal")
        };
        let (r, s) = sections_of(&b);
        assert_eq!(s[0].0, TAG_STOP_STATE);
        let rec = StopRecord::parse(&s[0].1).unwrap();
        assert_eq!(rec.kind, Kind::Refusal { request_digest: [0x22; 32] });
        assert_eq!((rec.state, rec.stop_epoch), (State::Stopped, 5));
        assert_eq!(s[1].0, TAG_TPM_NV_CERTIFY);
        assert_eq!(s.len(), 2, "no nonce on a refusal");
        let m = AttestationMessage::parse(&r.msg).unwrap();
        assert_eq!(m.counter, 5);
        assert_eq!(t.quoted.borrow()[0], stop_quote_qualifying(&r.msg));
    }

    #[test]
    fn the_certify_in_the_receipt_passes_the_verifier_check() {
        let t = Fake::at(3);
        let nonce = [9u8; 16];
        let b = status(&t, &ctx(), &nonce).unwrap();
        let (_, s) = sections_of(&b);
        assert_eq!(s[2], (TAG_VERIFIER_NONCE, nonce.to_vec()));
        let qd = certify_qualifying(&s[0].1, &nonce);
        let c = NvCertify::parse(&s[1].1).unwrap();
        check_counter_certify(&c.attest, &qd, &INDEX_NAME, 3).unwrap();
    }

    #[test]
    fn counter_moving_before_the_certify_denies_without_a_receipt() {
        let t = Fake::at(5);
        t.move_before_certify.set(true);
        let e = admit(&t, &ctx(), [0; 32]).unwrap_err();
        assert!(e.contains("the TPM read 6"), "{e}");
        assert!(t.quoted.borrow().is_empty(), "nothing gets quoted after a mismatch");
    }

    #[test]
    fn certify_of_another_index_denies_without_a_receipt() {
        let t = Fake::at(5);
        t.certify_other_index.set(true);
        assert!(admit(&t, &ctx(), [0; 32]).unwrap_err().contains("different NV index"));
        assert!(t.quoted.borrow().is_empty());
    }

    #[test]
    fn stop_quotes_never_use_the_agent_qualifying_data() {
        let t = Fake::at(2);
        let b = status(&t, &ctx(), &[]).unwrap();
        let r = Receipt::parse(&b).unwrap();
        let agent = attest_envelope::tpm::qualifying_data(&r.msg).unwrap();
        assert_ne!(t.quoted.borrow()[0].as_slice(), agent.as_slice());
    }

    #[test]
    fn bundle_digest_is_inside_the_quoted_message() {
        let t = Fake::at(2);
        let b = status(&t, &ctx(), &[]).unwrap();
        let r = Receipt::parse(&b).unwrap();
        let m = AttestationMessage::parse(&r.msg).unwrap();
        assert_eq!(m.evidence_hash, attest_envelope::evidence_digest(&r.bundle));
    }

    #[test]
    fn status_reports_running_and_stopped() {
        for (c, want) in [(6u64, State::Running), (7, State::Stopped)] {
            let b = status(&Fake::at(c), &ctx(), &[]).unwrap();
            let (_, s) = sections_of(&b);
            let rec = StopRecord::parse(&s[0].1).unwrap();
            assert_eq!((rec.kind, rec.state, rec.stop_epoch), (Kind::Status, want, c));
        }
    }

    #[test]
    fn bad_nonce_is_refused_before_touching_the_tpm() {
        let t = Fake::at(1);
        assert!(status(&t, &ctx(), &[0u8; 8]).is_err());
        assert!(t.certified.borrow().is_empty());
    }

    #[test]
    fn any_tpm_failure_is_an_error_not_an_allow() {
        let t = Fake::at(0);
        t.fail_reads_from.set(Some(1));
        assert!(admit(&t, &ctx(), [0; 32]).is_err());
        for set in [
            |f: &Fake| f.fail_certify.set(true),
            |f: &Fake| f.fail_quote.set(true),
        ] {
            let t = Fake::at(1);
            set(&t);
            assert!(admit(&t, &ctx(), [0; 32]).is_err());
        }
    }

    #[test]
    fn trip_and_recover_are_idempotent() {
        let t = Fake::at(0);
        assert_eq!(trip(&t).unwrap(), Transition::Changed { from: 0, to: 1 });
        assert_eq!(trip(&t).unwrap(), Transition::AlreadyThere { at: 1 });
        assert_eq!(t.counter.get(), 1, "a second trip must not un-stop the agent");
        assert_eq!(recover(&t).unwrap(), Transition::Changed { from: 1, to: 2 });
        assert_eq!(recover(&t).unwrap(), Transition::AlreadyThere { at: 2 });
        assert_eq!(t.counter.get(), 2);
    }

    #[test]
    fn failed_increment_reports_the_state_left_behind() {
        let t = Fake::at(4);
        t.fail_increment.set(true);
        let e = trip(&t).unwrap_err();
        assert_eq!(e.now, Some(4));
        assert_eq!(state_of(e.now.unwrap()), State::Running, "the agent is still running");
    }

    #[test]
    fn unreadable_counter_after_increment_is_reported_as_unknown() {
        let t = Fake::at(4);
        t.fail_reads_from.set(Some(2));
        let e = trip(&t).unwrap_err();
        assert!(e.message.contains("could not be read back"));
        assert_eq!(e.now, None);
        assert_eq!(t.counter.get(), 5, "the increment itself did happen");
    }

    #[test]
    fn a_second_writer_is_reported_with_the_resulting_state() {
        let t = Fake::at(4);
        t.double_increment.set(true);
        let e = trip(&t).unwrap_err();
        assert_eq!(e.now, Some(6));
        assert_eq!(state_of(6), State::Running, "the operator must be told the agent runs");
    }

    #[test]
    fn settle_fixes_the_parity_of_a_new_counter_once() {
        let t = Fake::at(8039);
        assert_eq!(settle(&t, State::Stopped).unwrap(), Transition::AlreadyThere { at: 8039 });
        let t = Fake::at(8040);
        assert_eq!(settle(&t, State::Stopped).unwrap(), Transition::Changed { from: 8040, to: 8041 });
    }

    #[test]
    fn receipt_message_width_matches_the_envelope() {
        assert_eq!(attest_stop::RECEIPT_MSG_LEN, MSG_LEN);
    }
}
