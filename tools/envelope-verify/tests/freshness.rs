//! The freshness option on the swtpm fixtures of attest-appraise: an envelope
//! whose counter is not above the given one is Stale, one above it goes on to
//! the state check.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

// The tests run in parallel; each reference gets a file of its own, or one
// test could read a file another is still writing.
static NEXT: AtomicUsize = AtomicUsize::new(0);

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../crates/attest-appraise/tests/fixtures/swtpm")
}

fn zero_reference() -> PathBuf {
    let z = "0".repeat(64);
    let pcr: Vec<String> = (0..10).map(|i| format!("\"{i}\":\"{z}\"")).collect();
    let p = std::env::temp_dir().join(format!("envelope-verify-zero-ref-{}-{}.json", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst)));
    std::fs::write(&p, format!(r#"{{"format":"tactiq-pcr-reference/2","bank":"sha256","pcr":{{{}}}}}"#, pcr.join(","))).unwrap();
    p
}

fn run(extra: &[&str]) -> (i32, String) {
    let f = fixtures();
    let out = Command::new(env!("CARGO_BIN_EXE_tactiq-envelope-verify"))
        .arg("check")
        .arg(f.join("v2"))
        .args(["--ak", f.join("ak.pub").to_str().unwrap()])
        .args(["--device", "rock5a-swtpm-01"])
        .args(["--pcr-ref", zero_reference().to_str().unwrap()])
        .args(extra)
        .output()
        .unwrap();
    (out.status.code().unwrap(), String::from_utf8(out.stdout).unwrap())
}

fn counter() -> u64 {
    let (_, out) = run(&[]);
    let line = out.lines().find(|l| l.starts_with("counter")).expect("counter line");
    line.split_whitespace().nth(1).unwrap().parse().unwrap()
}

#[test]
fn not_above_the_highest_accepted_is_stale() {
    let c = counter().to_string();
    let (code, out) = run(&["--highest-accepted", &c]);
    assert_eq!(code, 1);
    assert!(out.contains("VERDICT     REJECT Stale"), "{out}");
}

#[test]
fn above_the_highest_accepted_goes_on_to_the_state_check() {
    let c = (counter() - 1).to_string();
    let (code, out) = run(&["--highest-accepted", &c]);
    assert_eq!(code, 1);
    assert!(out.contains("REJECT UnrecognizedState"), "the zero reference must fail the state check, not freshness: {out}");
}

#[test]
fn without_the_option_freshness_is_not_judged() {
    let (_, out) = run(&[]);
    assert!(!out.contains("Stale"), "{out}");
    assert!(out.contains("not compared"), "{out}");
}
