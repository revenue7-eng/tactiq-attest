//! The decisions of the stop service, with no I/O of their own: what the
//! state is, whether a call passes, how a signed answer is assembled, and
//! what trip and recover do. Everything here runs against `StopTpm`.

use attest_envelope::{
    build_bundle, build_canonical, encode_pcr_selection, parse_bundle, MSG_LEN, TAG_STOP_STATE,
    TAG_TPM_NV_CERTIFY, TAG_VERIFIER_NONCE,
};
use attest_stop::{
    certify_qualifying, check_counter_certify, check_nonce, stop_quote_qualifying, Kind,
    NvCertify, Receipt, State, StopRecord,
};

use crate::port::{ReleaseStore, StopTpm, R};
use crate::release::{self, OperatorKey};

/// The parity of the stop counter: odd = stopped. Trip and recover each
/// advance it by one, so the parity changes only by an increment.
///
/// Parity alone does not let a call through. Anyone who can write the index
/// (the owner hierarchy, whose auth is empty on TactiQ OS) can advance it,
/// and the owner can delete and redefine it, so an even counter is running
/// only with the operator's release for that exact value (`gate`).
pub fn state_of(counter: u64) -> State {
    if counter.is_multiple_of(2) {
        State::Running
    } else {
        State::Stopped
    }
}

/// What lifting a stop is checked against: the device, the operator's
/// public key and where the release is read from.
pub struct Lift<'a> {
    pub device_id: &'a str,
    pub operator_key: &'a OperatorKey,
    pub release: &'a dyn ReleaseStore,
}

/// Whether a call may pass at this counter value.
#[derive(Debug, PartialEq, Eq)]
pub enum Gate {
    /// Even, with a valid release for exactly this value.
    Open,
    /// Odd: stopped.
    Stopped,
    /// Even, but no valid release for this value: still a stop. The reason
    /// says what was missing or wrong.
    Unreleased(String),
}

impl Gate {
    pub fn state(&self) -> State {
        match self {
            Gate::Open => State::Running,
            _ => State::Stopped,
        }
    }
}

/// Decide the gate for `counter`. An unreadable release is an error, which
/// every caller turns into a refusal; a missing or invalid one is a stop.
pub fn gate(lift: &Lift, counter: u64) -> R<Gate> {
    if state_of(counter) == State::Stopped {
        return Ok(Gate::Stopped);
    }
    Ok(match lift.release.read()? {
        None => Gate::Unreleased(format!("no operator release for epoch {counter}")),
        Some((rec, sig)) => match release::check(lift.operator_key, &rec, &sig, lift.device_id, counter) {
            Ok(()) => Gate::Open,
            Err(e) => Gate::Unreleased(e),
        },
    })
}

/// Fixed context of one service instance.
pub struct Ctx<'a> {
    pub lift: Lift<'a>,
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
    match gate(&ctx.lift, counter)? {
        Gate::Open => Ok(Admission::Allow),
        Gate::Stopped | Gate::Unreleased(_) => {
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
        state: gate(&ctx.lift, counter)?.state(),
        stop_epoch: counter,
        policy_digest: ctx.policy_digest,
    };
    sign(tpm, ctx, &rec, nonce)
}

/// The stop record a receipt carries, read back from the receipt itself, so
/// what a command reports about a receipt is what the receipt says. Parsing
/// only: this does not check the signatures.
pub fn record_of(receipt: &[u8]) -> R<StopRecord> {
    let r = Receipt::parse(receipt)?;
    let sections = parse_bundle(&r.bundle)?;
    match sections.iter().filter(|s| s.tag == TAG_STOP_STATE).collect::<Vec<_>>().as_slice() {
        [s] => StopRecord::parse(s.body),
        found => Err(format!("receipt: {} stop records, expected one", found.len())),
    }
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

/// Stop the agent. Needs no release and no key: anyone may stop it.
/// Idempotent: on an already odd counter it does nothing, so a repeated trip
/// cannot flip the state back to running. Callers hold the admin lock so two
/// operator commands cannot interleave their read and increment.
pub fn trip(tpm: &dyn StopTpm) -> Result<Transition, TransitionError> {
    move_to(tpm, State::Stopped)
}

/// Lift a stop, with the operator's release for the epoch the counter moves
/// to. The release is checked before the increment, so a missing or wrong
/// release changes nothing. On an even counter it does nothing if that value
/// already has a valid release, and fails if it has none: the agent is then
/// stopped, and lifting it takes a release for that value.
pub fn recover(tpm: &dyn StopTpm, lift: &Lift) -> Result<Transition, TransitionError> {
    let from = tpm.read_counter().map_err(|e| TransitionError { message: e, now: None })?;
    let target = if state_of(from) == State::Running { from } else { from + 1 };
    let refuse = |why: String| TransitionError {
        message: format!("no valid operator release for epoch {target}: {why}; nothing was changed"),
        now: Some(from),
    };
    match gate(lift, target) {
        Ok(Gate::Open) => {}
        Ok(Gate::Unreleased(why)) => return Err(refuse(why)),
        Ok(Gate::Stopped) => return Err(refuse("odd epoch".into())),
        Err(e) => return Err(refuse(e)),
    }
    if target == from {
        return Ok(Transition::AlreadyThere { at: from });
    }
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
    use crate::port::fake::{Fake, FakeRelease, INDEX_NAME};
    use crate::release::testkey;
    use attest_envelope::{parse_bundle, AttestationMessage};
    use std::sync::OnceLock;

    fn opkey() -> &'static OperatorKey {
        static K: OnceLock<OperatorKey> = OnceLock::new();
        K.get_or_init(testkey::key)
    }

    fn lift(r: &FakeRelease) -> Lift<'_> {
        Lift { device_id: "device-A", operator_key: opkey(), release: r }
    }

    /// A context reading its release from `r`.
    fn ctx_with(r: &FakeRelease) -> Ctx<'_> {
        Ctx { lift: lift(r), ..ctx() }
    }

    /// A context with a valid release for `epoch` (leaked: test only).
    fn released(epoch: u64) -> Ctx<'static> {
        ctx_with(Box::leak(Box::new(FakeRelease::signed("device-A", epoch))))
    }

    fn ctx() -> Ctx<'static> {
        Ctx {
            lift: Lift { device_id: "device-A", operator_key: opkey(), release: Box::leak(Box::new(FakeRelease::none())) },
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
        assert_eq!(admit(&t, &released(4), [0; 32]).unwrap(), Admission::Allow);
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
            let b = status(&Fake::at(c), &released(6), &[]).unwrap();
            let (_, s) = sections_of(&b);
            let rec = StopRecord::parse(&s[0].1).unwrap();
            assert_eq!((rec.kind, rec.state, rec.stop_epoch), (Kind::Status, want, c));
        }
    }

    #[test]
    fn record_of_reads_back_what_was_signed() {
        for (c, want) in [(6u64, State::Running), (7, State::Stopped)] {
            let rec = record_of(&status(&Fake::at(c), &released(6), &[]).unwrap()).unwrap();
            assert_eq!((rec.kind, rec.state, rec.stop_epoch), (Kind::Status, want, c));
        }
        let Admission::Refuse(b) = admit(&Fake::at(9), &ctx(), [7; 32]).unwrap() else {
            panic!("an odd counter must refuse")
        };
        let rec = record_of(&b).unwrap();
        assert_eq!((rec.kind, rec.state, rec.stop_epoch), (Kind::Refusal { request_digest: [7; 32] }, State::Stopped, 9));
    }

    #[test]
    fn record_of_refuses_what_is_not_a_receipt() {
        let b = status(&Fake::at(2), &ctx(), &[]).unwrap();
        assert!(record_of(&b[..b.len() - 1]).is_err(), "truncated");
        assert!(record_of(b"TQSR").is_err());
        assert!(record_of(&[]).is_err());
        let mut other = b.clone();
        other[0] = b'X';
        assert!(record_of(&other).is_err(), "wrong magic");
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
        let r = FakeRelease::signed("device-A", 2);
        assert_eq!(trip(&t).unwrap(), Transition::Changed { from: 0, to: 1 });
        assert_eq!(trip(&t).unwrap(), Transition::AlreadyThere { at: 1 });
        assert_eq!(t.counter.get(), 1, "a second trip must not un-stop the agent");
        assert_eq!(recover(&t, &lift(&r)).unwrap(), Transition::Changed { from: 1, to: 2 });
        assert_eq!(recover(&t, &lift(&r)).unwrap(), Transition::AlreadyThere { at: 2 });
        assert_eq!(t.counter.get(), 2);
    }

    #[test]
    fn an_even_counter_without_a_release_refuses_with_a_receipt() {
        // Parity flipped around recover (another TPM writer, a redefined index).
        let t = Fake::at(8);
        let Admission::Refuse(b) = admit(&t, &ctx(), [0x33; 32]).unwrap() else {
            panic!("no release: the call must be refused")
        };
        let rec = record_of(&b).unwrap();
        assert_eq!((rec.state, rec.stop_epoch), (State::Stopped, 8));
        assert_eq!(rec.kind, Kind::Refusal { request_digest: [0x33; 32] });
    }

    #[test]
    fn a_release_opens_only_its_own_epoch_on_its_own_device() {
        for (dev, ep, at) in [("device-A", 6u64, 8u64), ("device-A", 10, 8), ("device-B", 8, 8)] {
            let r = FakeRelease::signed(dev, ep);
            let a = admit(&Fake::at(at), &ctx_with(&r), [0; 32]).unwrap();
            assert!(matches!(a, Admission::Refuse(_)), "{dev} {ep} must not open {at}");
        }
        let r = FakeRelease::signed("device-A", 8);
        assert_eq!(admit(&Fake::at(8), &ctx_with(&r), [0; 32]).unwrap(), Admission::Allow);
    }

    #[test]
    fn an_altered_release_does_not_open() {
        let r = FakeRelease::signed("device-A", 8);
        {
            let mut f = r.files.borrow_mut();
            let (rec, _) = f.as_mut().unwrap();
            rec.push(b' ');
        }
        assert!(matches!(admit(&Fake::at(8), &ctx_with(&r), [0; 32]).unwrap(), Admission::Refuse(_)));
    }

    #[test]
    fn an_unreadable_release_is_an_error_not_an_allow() {
        let r = FakeRelease::signed("device-A", 8);
        r.fail.set(true);
        assert!(admit(&Fake::at(8), &ctx_with(&r), [0; 32]).is_err());
    }

    #[test]
    fn recover_without_a_valid_release_changes_nothing() {
        for r in [FakeRelease::none(), FakeRelease::signed("device-A", 4), FakeRelease::signed("device-B", 6)] {
            let t = Fake::at(5);
            let e = recover(&t, &lift(&r)).unwrap_err();
            assert!(e.message.contains("epoch 6"), "{}", e.message);
            assert_eq!(e.now, Some(5));
            assert_eq!(t.counter.get(), 5, "no increment without a release");
        }
    }

    #[test]
    fn a_used_release_does_not_lift_the_next_stop() {
        let t = Fake::at(5);
        let r = FakeRelease::signed("device-A", 6);
        recover(&t, &lift(&r)).unwrap();
        assert_eq!(admit(&t, &ctx_with(&r), [0; 32]).unwrap(), Admission::Allow);
        trip(&t).unwrap();
        assert!(recover(&t, &lift(&r)).is_err(), "the release for 6 does not name 8");
        assert_eq!(t.counter.get(), 7);
    }

    #[test]
    fn recover_on_an_even_counter_without_its_release_fails_and_says_stopped() {
        let t = Fake::at(8);
        let e = recover(&t, &lift(&FakeRelease::none())).unwrap_err();
        assert!(e.message.contains("epoch 8"), "{}", e.message);
        assert_eq!(t.counter.get(), 8);
        let r = FakeRelease::signed("device-A", 8);
        assert_eq!(recover(&t, &lift(&r)).unwrap(), Transition::AlreadyThere { at: 8 });
    }

    #[test]
    fn trip_needs_no_release() {
        let t = Fake::at(8);
        assert_eq!(trip(&t).unwrap(), Transition::Changed { from: 8, to: 9 });
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
