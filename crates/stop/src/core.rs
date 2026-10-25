//! The decisions of the stop service, with no I/O of their own: what the
//! state is, whether a call passes, how a signed answer is assembled, and
//! what trip and recover do. Everything here runs against `StopTpm`.

use attest_envelope::{
    build_bundle, build_canonical, encode_pcr_selection, MSG_LEN, TAG_STOP_STATE,
    TAG_TPM_NV_CERTIFY, TAG_VERIFIER_NONCE,
};
use attest_stop::{
    certify_qualifying, check_nonce, Kind, NvCertify, Receipt, State, StopRecord,
};

use crate::port::{StopTpm, R};

/// The stop state is the parity of the stop counter: odd = stopped. Trip and
/// recover each advance it by one, so the state can only change by an
/// increment, and an increment can never be undone.
pub fn state_of(counter: u64) -> State {
    if !counter.is_multiple_of(2) {
        State::Stopped
    } else {
        State::Running
    }
}

/// Fixed context of one service instance.
pub struct Ctx<'a> {
    pub device_id: &'a str,
    pub pcr_spec: &'a str,
    pub pcr_alg: u16,
    pub pcr_bitmap: [u8; 3],
    pub policy_digest: [u8; 32],
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
/// Order: the TPM certifies the counter with qualifying data bound to this
/// record (and nonce); record, certify and nonce go into the bundle; the
/// bundle's digest goes into the 93-byte message; the TPM quotes the PCRs
/// with qualifying data SHA-256(message). One check of the quote therefore
/// covers which build answered, what it said, and the TPM's own reading of
/// the counter. If the counter moved between the service's read and the
/// certify, the certified value differs from `stop_epoch` and a verifier
/// refuses the receipt: the race is detected, not hidden.
fn sign(tpm: &dyn StopTpm, ctx: &Ctx, rec: &StopRecord, nonce: &[u8]) -> R<Vec<u8>> {
    let body = rec.encode()?;
    let (c_attest, c_sig) = tpm.certify(&certify_qualifying(&body, nonce))?;
    let cert = NvCertify { attest: c_attest, sig: c_sig }.encode()?;

    let mut sections: Vec<(u16, &[u8])> = vec![(TAG_STOP_STATE, &body), (TAG_TPM_NV_CERTIFY, &cert)];
    if !nonce.is_empty() {
        sections.push((TAG_VERIFIER_NONCE, nonce));
    }
    let bundle = build_bundle(&sections)?;

    let pcr_state = tpm.pcr_read(ctx.pcr_spec)?;
    let selection = encode_pcr_selection(ctx.pcr_alg, ctx.pcr_bitmap);
    // The message counter carries the stop epoch. These envelopes are a
    // stream of their own, told apart by the stop record in the bundle; a
    // verifier must not feed them into the agent's high-water mark.
    let msg = build_canonical(ctx.device_id, rec.stop_epoch, &selection, &pcr_state, &bundle);
    if msg.len() != MSG_LEN {
        return Err(format!("built {} bytes, expected {MSG_LEN}", msg.len()));
    }
    let (q_attest, q_sig) = tpm.quote(&msg, ctx.pcr_spec)?;
    Receipt { msg, quote_attest: q_attest, quote_sig: q_sig, bundle }.encode()
}

/// What an operator command did.
#[derive(Debug, PartialEq, Eq)]
pub enum Transition {
    Changed { from: u64, to: u64 },
    AlreadyThere { at: u64 },
}

/// Stop the agent. Idempotent: on an already odd counter it does nothing, so
/// a repeated trip cannot flip the state back to running. Callers hold the
/// admin lock so two operator commands cannot interleave their read and
/// increment.
pub fn trip(tpm: &dyn StopTpm) -> R<Transition> {
    move_to(tpm, State::Stopped)
}

/// Lift a stop. Idempotent in the same way.
pub fn recover(tpm: &dyn StopTpm) -> R<Transition> {
    move_to(tpm, State::Running)
}

fn move_to(tpm: &dyn StopTpm, want: State) -> R<Transition> {
    let from = tpm.read_counter()?;
    if state_of(from) == want {
        return Ok(Transition::AlreadyThere { at: from });
    }
    tpm.increment()?;
    let to = tpm.read_counter()?;
    if to != from + 1 || state_of(to) != want {
        return Err(format!(
            "stop counter went from {from} to {to}; expected {} ({want:?}). Another writer moved it.",
            from + 1
        ));
    }
    Ok(Transition::Changed { from, to })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::port::fake::Fake;
    use attest_envelope::{parse_bundle, AttestationMessage};

    fn ctx() -> Ctx<'static> {
        Ctx {
            device_id: "device-A",
            pcr_spec: "sha256:0,1,8",
            pcr_alg: 0x000B,
            pcr_bitmap: [0x03, 0x01, 0x00],
            policy_digest: [0x11; 32],
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
        assert_eq!(t.quoted.borrow()[0], r.msg, "the quote covers this exact message");
    }

    #[test]
    fn certify_is_bound_to_the_record_and_nonce() {
        let t = Fake::at(3);
        let nonce = [9u8; 16];
        let b = status(&t, &ctx(), &nonce).unwrap();
        let (_, s) = sections_of(&b);
        assert_eq!(s[2], (TAG_VERIFIER_NONCE, nonce.to_vec()));
        let want = certify_qualifying(&s[0].1, &nonce);
        assert_eq!(t.certified.borrow()[0], want);
        let c = NvCertify::parse(&s[1].1).unwrap();
        assert!(c.attest.ends_with(&want), "fake certify echoes its qualifying data");
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
    fn unreadable_state_is_an_error_not_an_allow() {
        let t = Fake::at(0);
        t.fail_read.set(true);
        assert!(admit(&t, &ctx(), [0; 32]).is_err());
    }

    #[test]
    fn failed_signature_is_an_error_not_an_allow() {
        let t = Fake::at(1);
        t.fail_quote.set(true);
        assert!(admit(&t, &ctx(), [0; 32]).is_err());
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
    fn receipt_message_width_matches_the_envelope() {
        assert_eq!(attest_stop::RECEIPT_MSG_LEN, MSG_LEN);
    }
}
