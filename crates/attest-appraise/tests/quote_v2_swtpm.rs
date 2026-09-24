//! Envelope v2 (DDR-004) against bytes produced by a real TPM.
//!
//! Every fixture under `fixtures/swtpm/` came from swtpm 0.7.3 with tpm2-tools
//! 5.6, through the unmodified `tactiq-agent provision` and `attest` commands
//! (PCR spec `sha256:0,...,9`, PCR 3 extended once), plus direct tpm2-tools
//! calls for the negative cases. No signature here is produced by the test:
//! each one is the TPM's own.
//!
//!   ak.pub              TPM2B_PUBLIC of the AK at 0x81010003
//!   v2.msg/.attest/.sig one genuine v2 envelope, empty evidence bundle
//!   downgrade-v1.sig    tpm2_sign of v2.msg with the same AK (v1 form)
//!   fake-pcr.*          message with one bit of pcr_hash flipped, quoted with
//!                       qualifying data = SHA-256 of that message
//!   wrong-extra.*       genuine quote with qualifying data = SHA-256("other")
//!   other-sel.*         genuine quote for v2.msg, but over sha256:0,...,7
//!   not-ak.pub          ECC signing key without `restricted`

use attest_appraise::{authenticate_envelope, AkKey, Binding, Gate1Reject, Reason, TrustEntry};
use attest_envelope::tpm::EccPublic;
use p256::ecdsa::VerifyingKey;
use p256::EncodedPoint;

fn fx(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/swtpm/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn ak() -> TrustEntry { TrustEntry::Ak(AkKey::from_tpm2b_public(&fx("ak.pub")).expect("fixture AK must qualify")) }

/// The AK's raw verifying key, built outside `AkKey` on purpose: `AkKey` does
/// not hand it out, and this is how a careless trust store would hold it.
fn ak_as_legacy() -> TrustEntry {
    let pubb = fx("ak.pub");
    let p = EccPublic::parse_tpm2b(&pubb).unwrap();
    let pt = EncodedPoint::from_affine_coordinates(p.x.into(), p.y.into(), false);
    TrustEntry::Legacy(VerifyingKey::from_encoded_point(&pt).unwrap())
}

#[test]
fn case1_genuine_v2_envelope_is_accepted_as_tpm_quote() {
    let a = authenticate_envelope(&fx("v2.msg"), Some(&fx("v2.attest")), &fx("v2.sig"), b"", |_| Some(ak()))
        .expect("genuine v2 envelope must pass gate 1");
    assert_eq!(a.binding(), Binding::TpmQuote);
    assert!(a.quote_meta().is_some());
    assert_eq!(a.counter(), 2);
}

#[test]
fn case2_v1_envelope_signed_by_the_ak_is_refused() {
    let e = authenticate_envelope(&fx("v2.msg"), None, &fx("downgrade-v1.sig"), b"", |_| Some(ak())).unwrap_err();
    assert_eq!(e.reason, Gate1Reject::QuoteBindingFail);
    assert_eq!(Reason::from(e.reason), Reason::QuoteBindingFail);
}

#[test]
fn case2_the_downgrade_signature_is_real_which_is_why_decision_5_exists() {
    // The same bytes pass the v1 path if the AK is held as a bare key.
    let a = authenticate_envelope(&fx("v2.msg"), None, &fx("downgrade-v1.sig"), b"", |_| Some(ak_as_legacy()))
        .expect("a restricted AK does sign an arbitrary 93-byte message");
    assert_eq!(a.binding(), Binding::SelfSigned, "and it must never read as a quote");
}

#[test]
fn case3_altered_pcr_hash_is_refused_at_pcr_digest() {
    let e = authenticate_envelope(&fx("fake-pcr.msg"), Some(&fx("fake-pcr.attest")), &fx("fake-pcr.sig"), b"", |_| Some(ak()))
        .unwrap_err();
    assert_eq!(e.reason, Gate1Reject::QuoteBindingFail);
    assert!(e.detail.contains("pcrDigest"), "{}", e.detail);
}

#[test]
fn case4_quote_for_another_message_is_refused_at_extra_data() {
    let e = authenticate_envelope(&fx("v2.msg"), Some(&fx("wrong-extra.attest")), &fx("wrong-extra.sig"), b"", |_| Some(ak()))
        .unwrap_err();
    assert_eq!(e.reason, Gate1Reject::QuoteBindingFail);
    assert!(e.detail.contains("extraData"), "{}", e.detail);
}

#[test]
fn quote_over_a_different_pcr_selection_is_refused() {
    let e = authenticate_envelope(&fx("v2.msg"), Some(&fx("other-sel.attest")), &fx("other-sel.sig"), b"", |_| Some(ak()))
        .unwrap_err();
    assert_eq!(e.reason, Gate1Reject::QuoteBindingFail);
    assert!(e.detail.contains("selection"), "{}", e.detail);
}

#[test]
fn case5_key_without_restricted_is_not_an_ak() {
    let e = AkKey::from_tpm2b_public(&fx("not-ak.pub")).unwrap_err();
    assert!(e.contains("not an AK"), "{e}");
}

#[test]
fn quote_under_a_legacy_entry_is_refused() {
    let e = authenticate_envelope(&fx("v2.msg"), Some(&fx("v2.attest")), &fx("v2.sig"), b"", |_| Some(ak_as_legacy()))
        .unwrap_err();
    assert_eq!(e.reason, Gate1Reject::QuoteBindingFail);
}

#[test]
fn any_changed_byte_of_the_attest_fails_before_binding_checks() {
    let (m, a, s) = (fx("v2.msg"), fx("v2.attest"), fx("v2.sig"));
    for i in 0..a.len() {
        let mut t = a.clone();
        t[i] ^= 0x01;
        let e = authenticate_envelope(&m, Some(&t), &s, b"", |_| Some(ak())).unwrap_err();
        assert!(
            matches!(e.reason, Gate1Reject::SignatureFail | Gate1Reject::Malformed),
            "byte {i}: {:?} {}",
            e.reason,
            e.detail
        );
    }
}

#[test]
fn evidence_is_checked_only_after_the_quote_holds() {
    let e = authenticate_envelope(&fx("v2.msg"), Some(&fx("v2.attest")), &fx("v2.sig"), b"not-the-bundle", |_| Some(ak()))
        .unwrap_err();
    assert_eq!(e.reason, Gate1Reject::EvidenceBindingFail);
}
