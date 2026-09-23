//! Reference values and attested state — Decision 1a (locked, DDR-001).
//!
//! Reference value = an **opaque composite** `pcr_hash`. Appraisal = set-membership
//! against a small set of known-good composites. No per-PCR policy, no re-compute of
//! individual registers.

use crate::evidence::EvidenceKind;

/// Composite PCR digest, exactly as it rides inside the signed message.
/// Opaque bytes — this crate never parses or recomputes individual PCRs (Decision 1a).
/// Width is the TPM hash alg's digest size; SHA-256 => 32 bytes.
pub type PcrHash = [u8; 32];

/// Which PCRs the composite was computed over, plus the hash algorithm.
///
/// This rides inside attest-core's signed canonical envelope (as the opaque 5-byte
/// selection field) and is verified before the digest is compared (boundary A,
/// DDR-001). Otherwise an attacker quotes a composite over a *different* selection
/// (e.g. an empty one) whose digest collides with a golden value.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PcrSelection {
    /// TPM algorithm id (e.g. 0x000B = SHA-256).
    pub hash_alg: u16,
    /// Bitmap over PCR[0..23]: 24 registers -> 3 bytes, LSB = PCR0.
    pub pcr_mask: [u8; 3],
}

impl PcrSelection {
    /// Decode from attest-core's canonical opaque selection bytes:
    ///   `alg_id (u16, big-endian) || pcr_bitmap (3 bytes)`.
    /// Bijective with [`Self::to_canonical`]; bit order matches attest-core's
    /// encoder (PCR0 = LSB of bitmap byte 0), so this is a pure re-view of the same
    /// bytes, not a lossy adaptation.
    pub fn from_canonical(b: &[u8; attest_envelope::PCR_SELECTION_LEN]) -> Self {
        PcrSelection {
            hash_alg: u16::from_be_bytes([b[0], b[1]]),
            pcr_mask: [b[2], b[3], b[4]],
        }
    }

    /// Encode back to attest-core's canonical opaque selection bytes.
    pub fn to_canonical(&self) -> [u8; attest_envelope::PCR_SELECTION_LEN] {
        let a = self.hash_alg.to_be_bytes();
        [a[0], a[1], self.pcr_mask[0], self.pcr_mask[1], self.pcr_mask[2]]
    }
}

/// What the prover attested about device state, extracted from the (already
/// signature-verified) message. Both fields are covered by the signature.
#[derive(Clone, Debug)]
pub struct AttestedState {
    pub selection: PcrSelection,
    pub composite: PcrHash,
}

impl AttestedState {
    /// Gate 3's view of an authenticated envelope. The selection is re-viewed
    /// from its canonical bytes; the composite is copied verbatim. Both rode
    /// inside the signed area. Crate-private: the only way in is through
    /// [`crate::Authenticated`], so this state is never built from unverified
    /// bytes (DDR-003 boundary A).
    pub(crate) fn from_authenticated(a: &crate::Authenticated) -> Self {
        AttestedState {
            selection: PcrSelection::from_canonical(a.pcr_selection()),
            composite: *a.pcr_hash(),
        }
    }
}

/// The golden reference set — Decision 2 (locked).
///
/// Specifies the pair **(expected selection, set of allowed composites)**. Where
/// the set comes from, who signs it and how its own rollback is prevented are the
/// caller's business (DDR-001 decision 2); this crate only appraises against it.
pub struct ReferenceSet {
    pub expected_selection: PcrSelection,
    /// Small set of known-good composites (a device legitimately has a few good states).
    pub allowed: Vec<PcrHash>,
    /// Evidence kinds gate 3 demands beyond the envelope itself (decision 5 §5.2,
    /// §8 item 3). Order is the REPORTING priority: with several kinds missing,
    /// `EvidenceMissing` names the first one listed here (§5.2: one kind, no `Vec`).
    ///
    /// Never list `TpmQuote`. The host quote IS the signed envelope, proven by
    /// gate 1 by construction; listing it does not express "require a TPM" — it
    /// demands a *second* host quote inside the bundle, which no prover sends, so
    /// every appraisal of the device would reject `EvidenceMissing(TpmQuote)`.
    /// The failure is loud, not silent — a config error that announces itself on
    /// the first expected-accept — hence a doc rule, not an `insert` check.
    ///
    /// Empty is the honest edge-profile state, not a gap: the envelope is the
    /// entire evidence for a platform with no sub-attesters.
    pub required_evidence: Vec<EvidenceKind>,
}

impl ReferenceSet {
    /// `required_evidence` starts empty — the edge-profile default. Server-class
    /// profiles add kinds via [`Self::require`].
    pub fn new(expected_selection: PcrSelection, allowed: Vec<PcrHash>) -> Self {
        ReferenceSet { expected_selection, allowed, required_evidence: Vec::new() }
    }

    /// Builder step: demand an evidence kind. Call order = reporting priority
    /// (see `required_evidence`).
    pub fn require(mut self, kind: EvidenceKind) -> Self {
        self.required_evidence.push(kind);
        self
    }

    /// True iff `composite` is one of the known-good values. Set-membership is O(n)
    /// over a deliberately small set; cost is the same as a single compare for n=1.
    pub fn contains(&self, composite: &PcrHash) -> bool {
        self.allowed.iter().any(|g| g == composite)
    }
}
