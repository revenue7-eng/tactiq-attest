//! Verdict vocabulary: Decision 3 (locked, DDR-001), moved here unchanged by
//! DDR-003 decision 7, boundary D.
//!
//! One `Reason` for the whole pipeline, including failure classes this crate
//! never produces; keeping one enum keeps the verdict chain `Copy` and the
//! consumer unchanged.
//!
//! Structured `{outcome, reason}`, NOT a flat enum. Rationale: the fail-closed
//! state machine (item 4) consumes `outcome` for control-flow; `reason` carries
//! diagnostics. Splitting them here is free; splitting later is a refactor of a
//! type the automaton already depends on.

use crate::evidence::EvidenceKind;

/// Control-flow axis. Binary by design — the automaton branches on this alone.
/// Diagnostics never widen this enum (discarded in DDR-001: no per-gate outcomes).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    Accept,
    Reject,
}

/// Diagnostic axis. One variant per distinguishable failure class across the
/// whole pipeline, plus `Accepted`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reason {
    /// Every gate the producing function evaluates held. For [`crate::check`]
    /// and [`crate::appraise`] that is gate 1 and gate 3 only: the envelope is
    /// authentic, its bundle is bound, and the state was in the reference set at
    /// the moment of signing. Whether the envelope is the device's latest is NOT
    /// asserted (DDR-003 boundary B).
    Accepted,

    // ---- gate 1: authenticity (this crate, `authenticate`) ----
    /// ECDSA signature over the signed area did not verify.
    SignatureFail,
    /// no verifying key is known for this device_id.
    UnknownDevice,
    /// message could not be parsed into a well-formed attestation.
    Malformed,
    /// the attached evidence bundle did not hash to the signed `evidence_hash`.
    /// gate-1 class: the envelope signature verified, but the bundle that rode
    /// alongside it is not the one that was signed over.
    EvidenceBindingFail,

    // ---- classes produced by other verifiers, never by this crate ----
    /// the envelope is not the device's latest.
    Stale,
    /// the verifier could not record its decision.
    PersistFail,

    // ---- gate 3: device-state appraisal (this crate, `appraise`) ----
    /// attested (selection, composite) not recognized against the reference set.
    /// Diagnostically opaque by design (boundary D, DDR-001): does NOT distinguish
    /// "new legitimate un-enrolled state" from "compromise".
    UnrecognizedState,

    // ---- gate 3: evidence axis (this crate, decision 5 §5.2) ----
    /// the bundle bound to this envelope could not be parsed into sections.
    /// Distinct from `EvidenceMissing`: nothing is claimed about completeness,
    /// because the container itself is unreadable (boundary C, decision 6 — a
    /// bundle is fully parseable or refused, there is no valid prefix). Ordered
    /// ahead of the completeness variants: until the container parses, asking
    /// what it contains is meaningless. Carries no kind — the failure is the
    /// container, not a source.
    EvidenceUnparseable,
    /// the profile requires an evidence source of this kind and the bundle does
    /// not contain one. Reports ONE kind (§5.2: source axis inside `Reason`, no
    /// `Vec`); with several kinds missing, the first in the profile's
    /// `required_evidence` order. The payload is a field-less `Copy` enum, so the
    /// whole verdict chain stays `Copy` — that equivalence is what the §5.2 form
    /// was chosen for.
    EvidenceMissing(EvidenceKind),
    /// an evidence source of this kind was presented, appraised, and did not match
    /// its reference. Wired in §8 item 3; produced only once content appraisal
    /// exists (items 5/6) — dead until then BY DESIGN, same reason
    /// `outcome`/`reason` were split ahead of need in DDR-001: the automaton must
    /// not later survive a refactor of a type it already depends on.
    EvidenceUnrecognized(EvidenceKind),
}

/// A verdict. What `Accept` covers depends on which gates produced it; see
/// [`Reason::Accepted`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Verdict {
    pub outcome: Outcome,
    pub reason: Reason,
}

impl Verdict {
    pub const fn accept() -> Self {
        Verdict { outcome: Outcome::Accept, reason: Reason::Accepted }
    }

    pub const fn reject(reason: Reason) -> Self {
        Verdict { outcome: Outcome::Reject, reason }
    }

    pub fn is_accept(&self) -> bool {
        self.outcome == Outcome::Accept
    }
}
