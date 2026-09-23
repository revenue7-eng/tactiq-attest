//! attest-appraise: check one attestation envelope (DDR-003, decision 7).
//!
//! Gate 1 (signature under the device key, evidence binding) and gate 3
//! (device state against a reference set, evidence completeness) over the
//! `attest-envelope` wire format. Stateless: no clock, no filesystem, no
//! network, no randomness, builds for `wasm32-unknown-unknown`.
//!
//! What this crate answers: was this envelope signed by this key, is its bundle
//! the one that was signed over, and was the device state in the reference set
//! when it signed. What it does not answer: is this the device's latest envelope.

mod appraisal;
mod evidence;
mod gate1;
mod reference;
mod rim;
mod verdict;

pub use appraisal::{appraise, check};
pub use evidence::EvidenceKind;
pub use gate1::{authenticate, Authenticated, Gate1Error, Gate1Reject};
pub use reference::{AttestedState, PcrHash, PcrSelection, ReferenceSet};
pub use rim::reference_from_rim;
pub use verdict::{Outcome, Reason, Verdict};

#[cfg(test)]
mod tests;
