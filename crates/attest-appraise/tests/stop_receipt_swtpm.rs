//! Stop receipts (`verify_stop_receipt`) against bytes from a real TPM.
//!
//! The receipts in `fixtures/stop/` are real: `tactiq-stop` of this tree,
//! run against swtpm 0.7.3 with tpm2-tools 5.6, an AK made by `tpm2_createak` at the
//! service's handle, device id `TACTIQ-SWTPM-01`, PCRs 0, 1 and 8 at their
//! reset value (zero). `other-ak.pub` is a second AK of the same TPM.
//!
//! * `odd-stopped`: counter 3 after a trip, status with nonce N1;
//! * `even-norelease`: counter 2, no release on disk, status with N2;
//! * `even-running`: counter 2, the operator's release for 2, N2;
//! * `refusal`: the 403 body for one call at counter 3, no nonce;
//! * `forge-*`: made by `fixtures/stop/forge.py` as a process that can use
//!   the AK but cannot make the TPM read another counter value: the quote is
//!   the AK's, the record or certify lies. `forge-control` is built the same
//!   way honestly and must pass, so each refusal is the check's, not the
//!   script's. `forge-key` certifies with an unrestricted signing primary of
//!   the same TPM; `forge-index` certifies a second counter defined like the
//!   stop counter, at an odd value.

use attest_appraise::{verify_stop_receipt, AkKey, StopBasis, StopTrust};
use attest_envelope::tpm::Quote;
use attest_envelope::{parse_bundle, DEVICE_ID_LEN, TAG_STOP_STATE, TAG_TPM_NV_CERTIFY, TAG_VERIFIER_NONCE};
use attest_envelope::{build_bundle, evidence_digest};
use attest_stop::{stop_quote_qualifying, Kind, Receipt, State};
use sha2::{Digest, Sha256};

const N1: [u8; 32] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];
const N2: [u8; 16] = [0xa5; 16];
const ODD: &[u8] = include_bytes!("fixtures/stop/odd-stopped.tqsr");
const EVEN_NO: &[u8] = include_bytes!("fixtures/stop/even-norelease.tqsr");
const EVEN_RUN: &[u8] = include_bytes!("fixtures/stop/even-running.tqsr");
const REFUSAL: &[u8] = include_bytes!("fixtures/stop/refusal.tqsr");

fn ak() -> AkKey {
    AkKey::from_tpm2b_public(include_bytes!("fixtures/stop/ak.pub")).unwrap()
}

fn id(s: &str) -> [u8; DEVICE_ID_LEN] {
    let mut d = [0u8; DEVICE_ID_LEN];
    d[..s.len()].copy_from_slice(s.as_bytes());
    d
}

fn zero_composite() -> [u8; 32] {
    Sha256::digest([0u8; 96]).into()
}

fn trust<'a>(ak: &'a AkKey, nonce: Option<&'a [u8]>) -> StopTrust<'a> {
    StopTrust {
        ak,
        device_id: id("TACTIQ-SWTPM-01"),
        pcr_selection: attest_envelope::encode_pcr_selection(0x000B, [0x03, 0x01, 0x00]),
        pcr_composite: zero_composite(),
        nonce,
    }
}

#[test]
fn each_basis_is_read_from_a_real_receipt() {
    let k = ak();
    let f = verify_stop_receipt(ODD, &trust(&k, Some(&N1))).unwrap();
    assert_eq!((f.stop_epoch, f.state, f.fresh, f.basis()), (3, State::Stopped, true, StopBasis::Counter));
    assert_eq!(f.kind, Kind::Status);
    let f = verify_stop_receipt(EVEN_NO, &trust(&k, Some(&N2))).unwrap();
    assert_eq!((f.stop_epoch, f.basis()), (2, StopBasis::NoRelease));
    let f = verify_stop_receipt(EVEN_RUN, &trust(&k, Some(&N2))).unwrap();
    assert_eq!((f.stop_epoch, f.basis()), (2, StopBasis::Running));
}

#[test]
fn a_refusal_proves_what_was_said_but_is_not_fresh() {
    let k = ak();
    let f = verify_stop_receipt(REFUSAL, &trust(&k, None)).unwrap();
    assert!(matches!(f.kind, Kind::Refusal { .. }));
    assert_eq!((f.stop_epoch, f.fresh, f.basis()), (3, false, StopBasis::Counter));
    assert!(verify_stop_receipt(REFUSAL, &trust(&k, Some(&N1))).is_err(), "no nonce: not an answer to a challenge");
}

#[test]
fn an_answer_to_another_challenge_is_refused() {
    let k = ak();
    assert!(verify_stop_receipt(ODD, &trust(&k, Some(&N2))).is_err(), "replayed with another nonce");
    assert!(verify_stop_receipt(ODD, &trust(&k, None)).is_err(), "nonce present, none expected");
    let mut longer = N1.to_vec();
    longer.push(0);
    assert!(verify_stop_receipt(ODD, &trust(&k, Some(&longer))).is_err());
}

#[test]
fn another_key_device_or_build_is_refused() {
    let other = AkKey::from_tpm2b_public(include_bytes!("fixtures/stop/other-ak.pub")).unwrap();
    assert!(verify_stop_receipt(ODD, &trust(&other, Some(&N1))).is_err(), "another AK of the same TPM");
    let k = ak();
    let mut t = trust(&k, Some(&N1));
    t.device_id = id("TACTIQ-SWTPM-02");
    assert!(verify_stop_receipt(ODD, &t).is_err(), "another device id");
    let mut t = trust(&k, Some(&N1));
    t.pcr_composite[0] ^= 1;
    assert!(verify_stop_receipt(ODD, &t).is_err(), "another build");
    let mut t = trust(&k, Some(&N1));
    t.pcr_selection = attest_envelope::encode_pcr_selection(0x000B, [0xFF, 0x00, 0x00]);
    assert!(verify_stop_receipt(ODD, &t).is_err(), "other PCRs");
}

#[test]
fn any_altered_byte_is_refused() {
    let k = ak();
    // Past the magic and version, every byte is signed or is a length.
    for i in 0..ODD.len() {
        let mut b = ODD.to_vec();
        b[i] ^= 0x01;
        assert!(verify_stop_receipt(&b, &trust(&k, Some(&N1))).is_err(), "byte {i} altered and accepted");
    }
    assert!(verify_stop_receipt(&ODD[..ODD.len() - 1], &trust(&k, Some(&N1))).is_err());
}

fn split(r: &[u8]) -> Receipt {
    Receipt::parse(r).unwrap()
}

#[test]
fn parts_of_two_real_receipts_do_not_combine() {
    let k = ak();
    // Message and quote of the running answer, bundle of the stopped one.
    let mut mix = split(EVEN_RUN);
    mix.bundle = split(EVEN_NO).bundle;
    assert!(verify_stop_receipt(&mix.encode().unwrap(), &trust(&k, Some(&N2))).is_err());
    // A refusal's quote over a status message.
    let mut mix = split(ODD);
    let refusal = split(REFUSAL);
    mix.quote_attest = refusal.quote_attest;
    mix.quote_sig = refusal.quote_sig;
    assert!(verify_stop_receipt(&mix.encode().unwrap(), &trust(&k, Some(&N1))).is_err());
}

#[test]
fn a_certify_lifted_from_another_receipt_is_refused() {
    // Rebuild the bundle of the running answer around the stopped answer's
    // certify. Gets past nothing signed: the message's evidence_hash no
    // longer matches; and were the message re-signable, the certify's
    // qualifying data names another record.
    let run = split(EVEN_RUN);
    let no = split(EVEN_NO);
    let sec = |b: &[u8], tag| parse_bundle(b).unwrap().into_iter().find(|s| s.tag == tag).unwrap().body.to_vec();
    let bundle = build_bundle(&[
        (TAG_STOP_STATE, &sec(&run.bundle, TAG_STOP_STATE)),
        (TAG_TPM_NV_CERTIFY, &sec(&no.bundle, TAG_TPM_NV_CERTIFY)),
        (TAG_VERIFIER_NONCE, &N2),
    ])
    .unwrap();
    assert_ne!(evidence_digest(&bundle), evidence_digest(&run.bundle));
    let r = Receipt { bundle, ..run }.encode().unwrap();
    let k = ak();
    assert!(verify_stop_receipt(&r, &trust(&k, Some(&N2))).is_err());
}

// Forgeries by a process that can use the AK, made by
// `fixtures/stop/forge.py` against the same swtpm with the stop counter at 4 (even,
// running) and nonce N2. The quote in each is genuine: the AK signed it.
// Only the TPM's own read of the counter is out of the forger's reach.
const FORGE_CONTROL: &[u8] = include_bytes!("fixtures/stop/forge-control.tqsr");
const FORGE_EPOCH: &[u8] = include_bytes!("fixtures/stop/forge-epoch.tqsr");
const FORGE_KEY: &[u8] = include_bytes!("fixtures/stop/forge-key.tqsr");
const FORGE_INDEX: &[u8] = include_bytes!("fixtures/stop/forge-index.tqsr");

#[test]
fn the_forgery_script_builds_receipts_that_pass_when_honest() {
    let k = ak();
    let f = verify_stop_receipt(FORGE_CONTROL, &trust(&k, Some(&N2))).unwrap();
    assert_eq!((f.stop_epoch, f.basis()), (4, StopBasis::Running));
}

#[test]
fn a_stop_claimed_with_the_ak_but_not_read_by_the_tpm_is_refused() {
    let k = ak();
    let e = verify_stop_receipt(FORGE_EPOCH, &trust(&k, Some(&N2))).unwrap_err();
    assert!(e.contains("the TPM read 4, the record says 5"), "{e}");
    let e = verify_stop_receipt(FORGE_KEY, &trust(&k, Some(&N2))).unwrap_err();
    assert!(e.contains("nv certify: signature does not verify"), "{e}");
    let e = verify_stop_receipt(FORGE_INDEX, &trust(&k, Some(&N2))).unwrap_err();
    assert!(e.contains("different NV index"), "{e}");
}

#[test]
fn records_the_service_never_makes_are_refused_even_when_the_tpm_signed_them() {
    let k = ak();
    let t = trust(&k, Some(&N2));
    let e = verify_stop_receipt(include_bytes!("fixtures/stop/forge-msgcounter.tqsr"), &t).unwrap_err();
    assert!(e.contains("differs from the message counter"), "{e}");
    let e = verify_stop_receipt(include_bytes!("fixtures/stop/forge-refusal-nonce.tqsr"), &t).unwrap_err();
    assert!(e.contains("must be a status answer"), "{e}");
    // Made with the stop counter at 5.
    let e = verify_stop_receipt(include_bytes!("fixtures/stop/forge-oddrunning.tqsr"), &t).unwrap_err();
    assert!(e.contains("odd counter reported as running"), "{e}");
}

#[test]
fn an_agent_envelope_quote_never_passes_as_a_stop_receipt() {
    // Domain separation: the stop quote's extraData is not SHA-256(msg).
    let r = split(ODD);
    let q = Quote::parse(&r.quote_attest).unwrap();
    assert_ne!(q.extra_data, attest_envelope::tpm::qualifying_data(&r.msg).unwrap().as_slice());
    assert_eq!(q.extra_data, stop_quote_qualifying(&r.msg).as_slice());
}
