//! A stop that held from one receipt to a later one (`verify_stop_interval`),
//! against bytes from a real TPM.
//!
//! The receipts in `fixtures/stop/interval/` are `tactiq-stop status` of this
//! tree against swtpm 0.7.3 and tpm2-tools 5.6; the steps are in
//! `fixtures/stop/interval/make.sh`. One pair passes (`s1`, `s2`: one boot,
//! the same odd counter); every other pair differs from it in one thing the
//! check must see.

use attest_appraise::{verify_stop_interval, verify_stop_receipt, AkKey, StopTrust};
use attest_envelope::DEVICE_ID_LEN;
use sha2::{Digest, Sha256};

macro_rules! fx {
    ($name:literal) => {
        (
            include_bytes!(concat!("fixtures/stop/interval/", $name, ".tqsr")).as_slice(),
            unhex(include_str!(concat!("fixtures/stop/interval/", $name, ".nonce"))),
        )
    };
}

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn ak() -> AkKey {
    AkKey::from_tpm2b_public(include_bytes!("fixtures/stop/interval/ak.pub")).unwrap()
}

fn trust(ak: &AkKey) -> StopTrust<'_> {
    let mut device_id = [0u8; DEVICE_ID_LEN];
    device_id[..15].copy_from_slice(b"TACTIQ-SWTPM-01");
    StopTrust {
        ak,
        device_id,
        pcr_selection: attest_envelope::encode_pcr_selection(0x000B, [0x03, 0x01, 0x00]),
        pcr_composite: Sha256::digest([0u8; 96]).into(),
        nonce: None,
    }
}

fn interval(a: (&[u8], Vec<u8>), b: (&[u8], Vec<u8>)) -> Result<attest_appraise::StopInterval, String> {
    let k = ak();
    verify_stop_interval(a.0, &a.1, b.0, &b.1, &trust(&k))
}

#[test]
fn every_receipt_here_passes_on_its_own_except_the_mixed_one() {
    let k = ak();
    for (r, n) in [fx!("s1"), fx!("s2"), fx!("rs"), fx!("rb"), fx!("m0"), fx!("m2"), fx!("ev"), fx!("mix-no")] {
        let t = StopTrust { nonce: Some(&n), ..trust(&k) };
        verify_stop_receipt(r, &t).unwrap();
    }
    // So each refusal below is the interval check's, not the single one's.
}

#[test]
fn one_boot_and_the_same_odd_counter_held() {
    let v = interval(fx!("s1"), fx!("s2")).unwrap();
    assert_eq!(v.stop_epoch, 1);
    assert_eq!(v.from.reset_count, v.to.reset_count);
    assert!(v.held_ms() > 0);
}

#[test]
fn the_second_must_be_later() {
    let e = interval(fx!("s2"), fx!("s1")).unwrap_err();
    assert!(e.contains("not later"), "{e}");
}

#[test]
fn one_challenge_cannot_open_and_close_an_interval() {
    let (r1, n1) = fx!("s1");
    let (r2, _) = fx!("s2");
    let e = interval((r1, n1.clone()), (r2, n1)).unwrap_err();
    assert!(e.contains("same challenge"), "{e}");
}

#[test]
fn a_restart_in_between_is_refused() {
    let e = interval(fx!("s2"), fx!("rs")).unwrap_err();
    assert!(e.contains("restarted"), "{e}");
}

#[test]
fn a_reboot_in_between_is_refused() {
    let e = interval(fx!("rs"), fx!("rb")).unwrap_err();
    assert!(e.contains("reset in between"), "{e}");
}

#[test]
fn a_counter_that_moved_is_refused_even_when_odd_at_both_ends() {
    let e = interval(fx!("m0"), fx!("m2")).unwrap_err();
    assert!(e.contains("moved from 1 to 3"), "{e}");
}

#[test]
fn an_even_counter_is_not_a_stop_the_tpm_states() {
    let e = interval(fx!("m2"), fx!("ev")).unwrap_err();
    assert!(e.contains("even"), "{e}");
}

#[test]
fn an_altered_byte_in_either_receipt_is_refused() {
    let (r, n) = fx!("s2");
    let mut bad = r.to_vec();
    bad[200] ^= 0x01;
    assert!(interval(fx!("s1"), (&bad, n)).is_err());
}

#[test]
fn the_nonce_goes_to_the_interval_not_the_trust() {
    let k = ak();
    let (r1, n1) = fx!("s1");
    let (r2, n2) = fx!("s2");
    let t = StopTrust { nonce: Some(&n1), ..trust(&k) };
    assert!(verify_stop_interval(r1, &n1, r2, &n2, &t).is_err());
}

#[test]
fn a_counter_read_in_one_boot_and_a_build_quoted_in_another_do_not_make_one_receipt() {
    let k = ak();
    let (ok, n) = fx!("mix-no");
    verify_stop_receipt(ok, &StopTrust { nonce: Some(&n), ..trust(&k) }).unwrap();
    let (mixed, n) = fx!("mix-yes");
    let e = verify_stop_receipt(mixed, &StopTrust { nonce: Some(&n), ..trust(&k) }).unwrap_err();
    assert!(e.contains("another"), "{e}");
}
