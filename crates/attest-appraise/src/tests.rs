//! Tests drive real ECDSA P-256 signatures through `authenticate`: there is no
//! other way to obtain an `Authenticated`, which is the point (boundary A).
//! By-parts `gate3` is reachable here only because this module is inside the
//! crate.

use super::appraisal::gate3;
use super::*;
use attest_envelope::{build_bundle, build_canonical, encode_pcr_selection, evidence_digest, DEVICE_ID_LEN, TAG_GPU_ATTEST};
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};

// ---- fixtures ----

fn sk() -> SigningKey { SigningKey::from_slice(&[0x17u8; 32]).unwrap() }
fn vk() -> VerifyingKey { *sk().verifying_key() }
fn other_vk() -> VerifyingKey { *SigningKey::from_slice(&[0x29u8; 32]).unwrap().verifying_key() }

fn sel_0_7() -> PcrSelection { PcrSelection { hash_alg: 0x000B, pcr_mask: [0xFF, 0, 0] } }
fn sel_empty() -> PcrSelection { PcrSelection { hash_alg: 0x000B, pcr_mask: [0, 0, 0] } }

// `build_canonical` stores SHA-256(pcr_state) as the composite, and
// `evidence_digest` is SHA-256 of its input, so it doubles as the composite helper.
const STATE_A: &[u8] = b"pcr-state-A";
const STATE_B: &[u8] = b"pcr-state-B";
const STATE_ROGUE: &[u8] = b"pcr-state-rogue";
fn golden(state: &[u8]) -> PcrHash { evidence_digest(state) }

fn refset() -> ReferenceSet { ReferenceSet::new(sel_0_7(), vec![golden(STATE_A), golden(STATE_B)]) }

/// A signed envelope: (message, DER signature).
fn envelope(sel: &PcrSelection, state: &[u8], evidence: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let sel = encode_pcr_selection(sel.hash_alg, sel.pcr_mask);
    let msg = build_canonical("device-A", 7, &sel, state, evidence);
    let sig: Signature = sk().sign(&msg);
    (msg, sig.to_der().as_bytes().to_vec())
}

fn auth(sel: &PcrSelection, state: &[u8], evidence: &[u8]) -> Authenticated {
    let (m, s) = envelope(sel, state, evidence);
    authenticate(&m, &s, evidence, |_| Some(vk())).expect("fixture must pass gate 1")
}

// ---- gate 1 ----

#[test]
fn gate1_passes_a_legit_envelope_and_carries_the_signed_fields() {
    let a = auth(&sel_0_7(), STATE_A, b"");
    assert_eq!(&a.device_id()[..8], b"device-A");
    assert_eq!(a.counter(), 7);
    assert_eq!(a.pcr_hash(), &golden(STATE_A));
    assert_eq!(a.evidence(), b"");
}

#[test]
fn gate1_accepts_raw_r_s_as_well_as_der() {
    let (m, _) = envelope(&sel_0_7(), STATE_A, b"");
    let sig: Signature = sk().sign(&m);
    let raw = sig.to_bytes();
    assert!(authenticate(&m, &raw, b"", |_| Some(vk())).is_ok());
}

#[test]
fn gate1_malformed_has_no_device() {
    let e = authenticate(b"short", b"", b"", |_| Some(vk())).unwrap_err();
    assert_eq!(e.reason, Gate1Reject::Malformed);
    assert_eq!(e.device_id, None);
}

#[test]
fn gate1_unknown_device_when_lookup_returns_none() {
    let (m, s) = envelope(&sel_0_7(), STATE_A, b"");
    let e = authenticate(&m, &s, b"", |_| None).unwrap_err();
    assert_eq!(e.reason, Gate1Reject::UnknownDevice);
    assert_eq!(e.detail, "unknown device (not in trust store)");
}

#[test]
fn gate1_lookup_receives_the_device_id_from_the_signed_area() {
    let (m, s) = envelope(&sel_0_7(), STATE_A, b"");
    let mut seen = [0u8; DEVICE_ID_LEN];
    let _ = authenticate(&m, &s, b"", |id| { seen = *id; Some(vk()) });
    assert_eq!(&seen[..8], b"device-A");
}

#[test]
fn gate1_wrong_key_is_signature_fail() {
    let (m, s) = envelope(&sel_0_7(), STATE_A, b"");
    let e = authenticate(&m, &s, b"", |_| Some(other_vk())).unwrap_err();
    assert_eq!(e.reason, Gate1Reject::SignatureFail);
    assert_eq!(e.detail, "signature verification failed");
}

#[test]
fn gate1_tampered_selection_is_signature_fail() {
    let (mut m, s) = envelope(&sel_0_7(), STATE_A, b"");
    m[DEVICE_ID_LEN + 8 + 2] ^= 0x01;
    let e = authenticate(&m, &s, b"", |_| Some(vk())).unwrap_err();
    assert_eq!(e.reason, Gate1Reject::SignatureFail);
}

#[test]
fn gate1_undecodable_signature_is_signature_fail() {
    let (m, _) = envelope(&sel_0_7(), STATE_A, b"");
    let e = authenticate(&m, b"not-a-signature", b"", |_| Some(vk())).unwrap_err();
    assert_eq!(e.reason, Gate1Reject::SignatureFail);
    assert!(e.detail.starts_with("malformed signature: "));
}

#[test]
fn gate1_swapped_bundle_is_binding_fail_not_forgery() {
    let (m, s) = envelope(&sel_0_7(), STATE_A, b"signed-bundle");
    let e = authenticate(&m, &s, b"other-bundle", |_| Some(vk())).unwrap_err();
    assert_eq!(e.reason, Gate1Reject::EvidenceBindingFail);
    assert_eq!(e.detail, "evidence binding: bundle of 12 byte(s) does not hash to the signed digest");
}

#[test]
fn gate1_dropped_bundle_is_binding_fail() {
    let (m, s) = envelope(&sel_0_7(), STATE_A, b"signed-bundle");
    let e = authenticate(&m, &s, b"", |_| Some(vk())).unwrap_err();
    assert_eq!(e.reason, Gate1Reject::EvidenceBindingFail);
}

#[test]
fn gate1_signature_is_checked_before_binding() {
    // Forged signature AND swapped bundle: the signature failure is reported.
    // Before the signature holds, `evidence_hash` is attacker-chosen.
    let (m, s) = envelope(&sel_0_7(), STATE_A, b"signed-bundle");
    let e = authenticate(&m, &s, b"other", |_| Some(other_vk())).unwrap_err();
    assert_eq!(e.reason, Gate1Reject::SignatureFail);
}

// ---- gate 3 via appraise ----

#[test]
fn accept_when_selection_matches_and_composite_in_set() {
    let v = appraise(&auth(&sel_0_7(), STATE_A, b""), &refset());
    assert_eq!(v, Verdict::accept());
}

#[test]
fn accept_on_second_known_good_state() {
    assert!(appraise(&auth(&sel_0_7(), STATE_B, b""), &refset()).is_accept());
}

#[test]
fn unrecognized_when_composite_not_in_set() {
    let v = appraise(&auth(&sel_0_7(), STATE_ROGUE, b""), &refset());
    assert_eq!(v, Verdict::reject(Reason::UnrecognizedState));
}

#[test]
fn selection_mismatch_rejects_even_if_composite_would_match() {
    // Boundary A, DDR-001: a golden composite over the wrong selection.
    let v = appraise(&auth(&sel_empty(), STATE_A, b""), &refset());
    assert_eq!(v, Verdict::reject(Reason::UnrecognizedState));
}

fn refset_requiring_gpu() -> ReferenceSet {
    ReferenceSet::new(sel_0_7(), vec![golden(STATE_A)]).require(EvidenceKind::GpuAttest)
}

#[test]
fn evidence_missing_when_required_kind_absent() {
    let v = appraise(&auth(&sel_0_7(), STATE_A, b""), &refset_requiring_gpu());
    assert_eq!(v, Verdict::reject(Reason::EvidenceMissing(EvidenceKind::GpuAttest)));
}

#[test]
fn required_kind_satisfied_by_a_presented_section() {
    let bundle = build_bundle(&[(TAG_GPU_ATTEST, b"token")]).unwrap();
    assert!(appraise(&auth(&sel_0_7(), STATE_A, &bundle), &refset_requiring_gpu()).is_accept());
}

#[test]
fn state_is_appraised_before_evidence_completeness() {
    let v = appraise(&auth(&sel_0_7(), STATE_ROGUE, b""), &refset_requiring_gpu());
    assert_eq!(v, Verdict::reject(Reason::UnrecognizedState));
}

#[test]
fn unparseable_bound_bundle_is_refused_not_empty() {
    // Bound (it passes gate 1) but not a valid container: truncated header.
    let v = appraise(&auth(&sel_0_7(), STATE_A, &[0x00, 0x02, 0x00]), &refset());
    assert_eq!(v, Verdict::reject(Reason::EvidenceUnparseable));
}

#[test]
fn first_missing_kind_in_profile_order_is_reported() {
    let refs = ReferenceSet::new(sel_0_7(), vec![golden(STATE_A)])
        .require(EvidenceKind::CpuTee)
        .require(EvidenceKind::GpuAttest);
    let st = AttestedState { selection: sel_0_7(), composite: golden(STATE_A) };
    assert_eq!(gate3(&st, &[], &refs), Verdict::reject(Reason::EvidenceMissing(EvidenceKind::CpuTee)));
    assert_eq!(
        gate3(&st, &[EvidenceKind::CpuTee], &refs),
        Verdict::reject(Reason::EvidenceMissing(EvidenceKind::GpuAttest))
    );
}

// ---- check: gate 1 then gate 3 ----

#[test]
fn check_accepts_end_to_end() {
    let (m, s) = envelope(&sel_0_7(), STATE_A, b"");
    assert_eq!(check(&m, &s, b"", &vk(), &refset()), Verdict::accept());
}

#[test]
fn check_reports_gate1_before_gate3() {
    // Rogue state under the wrong key: the forgery is reported, not the state.
    let (m, s) = envelope(&sel_0_7(), STATE_ROGUE, b"");
    assert_eq!(check(&m, &s, b"", &other_vk(), &refset()), Verdict::reject(Reason::SignatureFail));
}

#[test]
fn check_reports_binding_failure() {
    let (m, s) = envelope(&sel_0_7(), STATE_A, b"signed-bundle");
    assert_eq!(check(&m, &s, b"", &vk(), &refset()), Verdict::reject(Reason::EvidenceBindingFail));
}

#[test]
fn gate1_reject_maps_onto_reason() {
    for (g, r) in [
        (Gate1Reject::Malformed, Reason::Malformed),
        (Gate1Reject::UnknownDevice, Reason::UnknownDevice),
        (Gate1Reject::SignatureFail, Reason::SignatureFail),
        (Gate1Reject::EvidenceBindingFail, Reason::EvidenceBindingFail),
    ] {
        assert_eq!(Reason::from(g), r);
    }
}

#[test]
fn verdict_chain_stays_copy() {
    fn assert_copy<T: Copy>() {}
    assert_copy::<EvidenceKind>();
    assert_copy::<Reason>();
    assert_copy::<Outcome>();
    assert_copy::<Verdict>();
    assert_copy::<Gate1Reject>();
}
