//! End-to-end coverage of every sign-fingerprints subcommand and exit
//! path. Each test sets up a synthetic registry directory in a tempdir
//! to keep the suite hermetic.

use assert_cmd::Command;
use predicates::str::contains;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn seed_registry(dir: &Path) {
    fs::write(dir.join("alpha.json"), b"{\"alpha\":1}").expect("write alpha");
    fs::write(dir.join("beta.json"), b"{\"beta\":2}").expect("write beta");
}

#[test]
fn recompute_writes_placeholder_envelope_covering_every_file() {
    let dir = TempDir::new().expect("tempdir");
    seed_registry(dir.path());
    Command::cargo_bin("sign-fingerprints")
        .expect("bin")
        .args(["recompute", "--registry-dir"])
        .arg(dir.path())
        .assert()
        .success();
    let envelope = fs::read_to_string(dir.path().join("registry-manifest.json")).expect("read");
    assert!(envelope.contains("\"placeholder\":true"));
    assert!(envelope.contains("\"alpha.json\""));
    assert!(envelope.contains("\"beta.json\""));
    // Self-referencing files are excluded from coverage rows.
    assert!(!envelope.contains("\"registry-manifest.json\""));
    assert!(!envelope.contains("\"registry-manifest.sigstore\""));
}

#[test]
fn verify_passes_on_freshly_recomputed_placeholder_without_require_signed() {
    let dir = TempDir::new().expect("tempdir");
    seed_registry(dir.path());
    Command::cargo_bin("sign-fingerprints")
        .expect("bin")
        .args(["recompute", "--registry-dir"])
        .arg(dir.path())
        .assert()
        .success();
    Command::cargo_bin("sign-fingerprints")
        .expect("bin")
        .args(["verify", "--registry-dir"])
        .arg(dir.path())
        .assert()
        .success()
        .stderr(contains("placeholder"));
}

#[test]
fn verify_refuses_placeholder_when_require_signed_is_set() {
    let dir = TempDir::new().expect("tempdir");
    seed_registry(dir.path());
    Command::cargo_bin("sign-fingerprints")
        .expect("bin")
        .args(["recompute", "--registry-dir"])
        .arg(dir.path())
        .assert()
        .success();
    Command::cargo_bin("sign-fingerprints")
        .expect("bin")
        .args(["verify", "--registry-dir"])
        .arg(dir.path())
        .arg("--require-signed")
        .assert()
        .failure()
        .stderr(contains("placeholder"));
}

#[test]
fn verify_fails_when_a_covered_file_is_edited() {
    let dir = TempDir::new().expect("tempdir");
    seed_registry(dir.path());
    Command::cargo_bin("sign-fingerprints")
        .expect("bin")
        .args(["recompute", "--registry-dir"])
        .arg(dir.path())
        .assert()
        .success();
    fs::write(dir.path().join("alpha.json"), b"{\"alpha\":\"tampered\"}").expect("tamper");
    Command::cargo_bin("sign-fingerprints")
        .expect("bin")
        .args(["verify", "--registry-dir"])
        .arg(dir.path())
        .assert()
        .failure()
        .stderr(contains("content gate failed"));
}

#[test]
fn verify_fails_when_a_new_file_is_added_after_signing() {
    let dir = TempDir::new().expect("tempdir");
    seed_registry(dir.path());
    Command::cargo_bin("sign-fingerprints")
        .expect("bin")
        .args(["recompute", "--registry-dir"])
        .arg(dir.path())
        .assert()
        .success();
    fs::write(dir.path().join("gamma.json"), b"{\"gamma\":3}").expect("add gamma");
    Command::cargo_bin("sign-fingerprints")
        .expect("bin")
        .args(["verify", "--registry-dir"])
        .arg(dir.path())
        .assert()
        .failure()
        .stderr(contains("content gate failed"));
}

#[test]
fn flip_placeholder_refuses_without_bundle() {
    let dir = TempDir::new().expect("tempdir");
    seed_registry(dir.path());
    Command::cargo_bin("sign-fingerprints")
        .expect("bin")
        .args(["recompute", "--registry-dir"])
        .arg(dir.path())
        .assert()
        .success();
    Command::cargo_bin("sign-fingerprints")
        .expect("bin")
        .args(["flip-placeholder", "--registry-dir"])
        .arg(dir.path())
        .assert()
        .failure()
        .stderr(contains("registry-manifest.sigstore"));
}

#[test]
fn flip_placeholder_succeeds_with_bundle_present_and_rewrites_envelope() {
    let dir = TempDir::new().expect("tempdir");
    seed_registry(dir.path());
    Command::cargo_bin("sign-fingerprints")
        .expect("bin")
        .args(["recompute", "--registry-dir"])
        .arg(dir.path())
        .assert()
        .success();
    // Synthesize a bundle file. Its contents are not checked by
    // flip-placeholder; signature validation happens later, in
    // verify --require-signed against a real cosign output.
    fs::write(
        dir.path().join("registry-manifest.sigstore"),
        b"{\"placeholder-bundle\":true}",
    )
    .expect("write bundle");
    Command::cargo_bin("sign-fingerprints")
        .expect("bin")
        .args(["flip-placeholder", "--registry-dir"])
        .arg(dir.path())
        .assert()
        .success();
    let envelope =
        fs::read_to_string(dir.path().join("registry-manifest.json")).expect("read envelope");
    assert!(envelope.contains("\"placeholder\":false"));
    assert!(envelope.contains("\"signed_at_utc\""));
    // placeholder_reason must be omitted from the canonical bytes.
    assert!(
        !envelope.contains("\"placeholder_reason\""),
        "placeholder_reason must not survive the flip: {envelope}"
    );
}
