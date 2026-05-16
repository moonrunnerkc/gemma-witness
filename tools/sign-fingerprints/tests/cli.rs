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
fn finalize_rewrites_envelope_with_placeholder_false_and_signed_at_utc() {
    let dir = TempDir::new().expect("tempdir");
    seed_registry(dir.path());
    Command::cargo_bin("sign-fingerprints")
        .expect("bin")
        .args(["finalize", "--registry-dir"])
        .arg(dir.path())
        .assert()
        .success();
    let envelope =
        fs::read_to_string(dir.path().join("registry-manifest.json")).expect("read envelope");
    assert!(envelope.contains("\"placeholder\":false"));
    assert!(envelope.contains("\"signed_at_utc\""));
    assert!(
        !envelope.contains("\"placeholder_reason\""),
        "placeholder_reason must not survive finalize: {envelope}"
    );
}

#[test]
fn finalize_then_verify_refuses_without_a_real_signature_bundle() {
    // finalize alone is not enough; verify --require-signed must still
    // fail until cosign produces registry-manifest.sigstore. This is the
    // gate that protects against a workflow regression that finalizes
    // but forgets to actually run cosign sign-blob.
    let dir = TempDir::new().expect("tempdir");
    seed_registry(dir.path());
    Command::cargo_bin("sign-fingerprints")
        .expect("bin")
        .args(["finalize", "--registry-dir"])
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
        .stderr(contains("signature gate failed"));
}
