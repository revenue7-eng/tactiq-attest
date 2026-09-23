//! Gate 3 (device-state appraisal) over an authenticated envelope, and the
//! single-envelope check that composes gate 1 with it (DDR-003, decision 7).
//!
//! The only public entry into gate 3 is [`appraise`], which takes an
//! [`Authenticated`]. The by-parts `gate3` is crate-private: exposing it would let
//! a caller hand in any state and any list of sources and skip gate 1 entirely
//! (DDR-003 boundary A).

use p256::ecdsa::VerifyingKey;

use crate::evidence::EvidenceKind;
use crate::gate1::{authenticate, Authenticated};
use crate::reference::{AttestedState, ReferenceSet};
use crate::verdict::{Reason, Verdict};

/// Gate 3 over an envelope that passed gate 1.
///
/// Parses the bound bundle into presented kinds, then appraises state before
/// evidence. An unparseable bundle is a refusal, never an empty presentation
/// (DDR-002 decision 6, boundary C): degrading it to "nothing presented" would let
/// a garbled bundle read as a device with no sub-attesters.
pub fn appraise(auth: &Authenticated, refs: &ReferenceSet) -> Verdict {
    match presented_kinds(auth.evidence()) {
        Ok(kinds) => gate3(&AttestedState::from_authenticated(auth), &kinds, refs),
        Err(_) => Verdict::reject(Reason::EvidenceUnparseable),
    }
}

/// Check one envelope: gate 1 under `key`, then gate 3 against `refs`.
///
/// `Accept` means the envelope was signed by `key`, its bundle is bound, and the
/// device state was in `refs` at the moment of signing. It says nothing about
/// whether this is the device's latest envelope (DDR-003 boundary B).
pub fn check(
    msg_bytes: &[u8],
    sig_bytes: &[u8],
    evidence: &[u8],
    key: &VerifyingKey,
    refs: &ReferenceSet,
) -> Verdict {
    match authenticate(msg_bytes, sig_bytes, evidence, |_| Some(*key)) {
        Ok(auth) => appraise(&auth, refs),
        Err(e) => Verdict::reject(e.reason.into()),
    }
}

/// Gate 3: appraise attested device state, then evidence completeness, against the
/// device's reference set.
///
/// Axis order — **state before evidence** (ratified 2026-08-25; implementation of
/// §5.3, the inter-gate order stays locked by decision 3). The single `reason` goes
/// to the heaviest failed layer, matching the pipeline-wide convention
/// (an earlier gate's failure is reported before a later one's): evidence *extends*
/// the state verifier (decision 5 over decision 1a), so a failure of the extension
/// must not mask a failure of the core. In RFC 9334 composite-device terms the host
/// is the lead attester and collector — distrust of the collector precedes any
/// question about what it collected. Discarded (do not revive): evidence-first on
/// the grounds that `EvidenceMissing(kind)` is precise while `UnrecognizedState` is
/// opaque — precision is the wrong axis, severity is the right one; either order
/// surfaces the other failure one re-attestation cycle later, and in an air-gapped
/// deployment a cycle is a site visit, so the heavy signal goes first.
///
/// Within each axis: context before value (selection -> composite, boundary A,
/// DDR-001 — a correctness invariant, not a preference) and presence before content
/// (completeness here; content appraisal of presented sources lands with §8
/// items 5/6 and will produce `EvidenceUnrecognized`).
///
/// `UnrecognizedState` is a REJECT outcome, but it is NOT tamper: the device may
/// have honestly attested an un-enrolled state. The distinction from forgery
/// (SignatureFail, gate 1) is what lets the automaton quarantine vs. alarm.
pub(crate) fn gate3(attested: &AttestedState, presented: &[EvidenceKind], refs: &ReferenceSet) -> Verdict {
    // ---- state axis (decision 1a) ----

    // (1) Selection gate — must match before any digest comparison. If the prover
    // quoted over a different register set, the composite is meaningless against our
    // reference regardless of whether its bytes happen to collide with a golden value.
    if attested.selection != refs.expected_selection {
        return Verdict::reject(Reason::UnrecognizedState);
    }

    // (2) Set-membership on the opaque composite.
    if !refs.contains(&attested.composite) {
        return Verdict::reject(Reason::UnrecognizedState);
    }

    // ---- evidence axis (decision 5, §8 item 3) ----

    // (3) Completeness: every kind the profile requires must be presented. Reports
    // the FIRST missing kind in profile order (§5.2: one kind, no Vec; profile
    // order = reporting priority).
    if let Some(missing) = refs.required_evidence.iter().find(|k| !presented.contains(k)) {
        return Verdict::reject(Reason::EvidenceMissing(*missing));
    }

    // (4) Content appraisal of presented sources — §8 items 5/6. Until then,
    // presence is the entire evidence axis.

    Verdict::accept()
}

/// Which evidence kinds the bundle actually presents.
///
/// Boundary B: a tag with no `EvidenceKind` is skipped, not an error — this
/// verifier appraises the sources it knows and is silent about the rest.
/// Boundary E: repeated tags are legitimate on the wire; gate 3 asks about
/// presence, so the list is deduplicated.
fn presented_kinds(bundle: &[u8]) -> Result<Vec<EvidenceKind>, String> {
    let mut out: Vec<EvidenceKind> = Vec::new();
    for section in attest_envelope::parse_bundle(bundle)? {
        if let Some(kind) = EvidenceKind::from_tag(section.tag) {
            if !out.contains(&kind) {
                out.push(kind);
            }
        }
    }
    Ok(out)
}
