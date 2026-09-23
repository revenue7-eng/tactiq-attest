//! Evidence-source vocabulary — Decision 5 §5.2 (locked, DDR-002).
//!
//! Names the *kind* of an evidence source, nothing else. Deliberately a field-less
//! C-like enum: `Copy` here is exactly what lets `Reason` carry a kind as payload
//! without forfeiting `Copy` on the whole verdict chain (§5.2 [FACT]).
//!
//! Dependency-free by design: this module is the top of the crate's DAG
//! (`evidence -> {verdict, reference} -> appraisal`). It must not grow imports from
//! `reference` — that would invert the layering.

/// Kind of an attestation evidence source. In RFC 9334 composite-device terms the
/// host is the lead attester and collector; the bundle carries sub-attesters.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EvidenceKind {
    /// The host TPM quote — the signed envelope itself. Structurally present on
    /// every message that clears gate 1; see `ReferenceSet::required_evidence` for
    /// why profiles must NOT list it as required.
    TpmQuote,
    /// GPU attestation token (server segment; §8 item 5).
    GpuAttest,
    /// CPU confidential-computing report — Intel TDX / AMD SEV-SNP. Deferred behind
    /// an explicit condition (decision 5 boundary B); §8 item 6.
    CpuTee,
}

impl EvidenceKind {
    /// Wire tag -> kind. `None` is not an error: an unknown tag (including the
    /// private range) is a source this verifier does not appraise, not a
    /// malformed bundle (boundary B, DDR-002 decision 6).
    pub fn from_tag(tag: u16) -> Option<Self> {
        match tag {
            attest_envelope::TAG_TPM_QUOTE => Some(Self::TpmQuote),
            attest_envelope::TAG_GPU_ATTEST => Some(Self::GpuAttest),
            attest_envelope::TAG_CPU_TEE => Some(Self::CpuTee),
            _ => None,
        }
    }
}
