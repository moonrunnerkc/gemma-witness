//! End-to-end tests for the check-pinned-binary CLI.
//!
//! Each test materializes a temp PINNED.json and a temp fake binary with
//! known bytes, then invokes the compiled CLI binary via `assert_cmd`. The
//! tests exercise every typed exit code, the `--target-triple` override, and
//! the `--allow-local-dev` downgrade.

use std::fs;
use std::process::Command;

use assert_cmd::prelude::*;
use predicates::str::contains;

const REAL_HASH_OF_HELLO_WORLD: &str =
    "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

fn write_binary(dir: &std::path::Path, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.join("fake-mistralrs");
    fs::write(&path, bytes).unwrap();
    path
}

fn write_pinned(dir: &std::path::Path, contents: &str) -> std::path::PathBuf {
    let path = dir.join("PINNED.json");
    fs::write(&path, contents).unwrap();
    path
}

fn cmd() -> Command {
    Command::cargo_bin("check-pinned-binary").expect("binary builds")
}

#[test]
fn passes_when_hash_matches_known_triple() {
    let dir = tempfile::tempdir().unwrap();
    let bin = write_binary(dir.path(), b"hello world");
    let pinned = write_pinned(
        dir.path(),
        &format!(
            r#"{{
                "schema_version": 1,
                "upstream_commit": "abc",
                "placeholder": false,
                "binaries": [
                    {{ "target_triple": "x86_64-unknown-linux-gnu", "sha256": "{REAL_HASH_OF_HELLO_WORLD}" }}
                ]
            }}"#
        ),
    );
    cmd()
        .args([
            "--pinned",
            pinned.to_str().unwrap(),
            "--binary",
            bin.to_str().unwrap(),
            "--target-triple",
            "x86_64-unknown-linux-gnu",
        ])
        .assert()
        .success()
        .stdout(contains("ok target_triple=x86_64-unknown-linux-gnu"));
}

#[test]
fn rejects_when_hash_mismatches() {
    let dir = tempfile::tempdir().unwrap();
    let bin = write_binary(dir.path(), b"hello world");
    let pinned = write_pinned(
        dir.path(),
        r#"{
            "schema_version": 1,
            "upstream_commit": "abc",
            "placeholder": false,
            "binaries": [
                { "target_triple": "x86_64-unknown-linux-gnu", "sha256": "0000000000000000000000000000000000000000000000000000000000000000" }
            ]
        }"#,
    );
    let assert = cmd()
        .args([
            "--pinned",
            pinned.to_str().unwrap(),
            "--binary",
            bin.to_str().unwrap(),
            "--target-triple",
            "x86_64-unknown-linux-gnu",
        ])
        .assert()
        .failure()
        .stderr(contains("has SHA-256"))
        .stderr(contains("but PINNED.json expects"));
    let code = assert
        .get_output()
        .status
        .code()
        .expect("exit code present");
    assert_eq!(code, 66, "hash mismatch exit code");
}

#[test]
fn rejects_when_pinned_is_placeholder() {
    let dir = tempfile::tempdir().unwrap();
    let bin = write_binary(dir.path(), b"hello world");
    let pinned = write_pinned(
        dir.path(),
        r#"{
            "schema_version": 1,
            "upstream_commit": "0000",
            "placeholder": true,
            "binaries": []
        }"#,
    );
    let assert = cmd()
        .args([
            "--pinned",
            pinned.to_str().unwrap(),
            "--binary",
            bin.to_str().unwrap(),
            "--target-triple",
            "x86_64-unknown-linux-gnu",
        ])
        .assert()
        .failure()
        .stderr(contains("placeholder=true"));
    assert_eq!(assert.get_output().status.code(), Some(64));
}

#[test]
fn rejects_when_triple_is_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let bin = write_binary(dir.path(), b"hello world");
    let pinned = write_pinned(
        dir.path(),
        &format!(
            r#"{{
                "schema_version": 1,
                "upstream_commit": "abc",
                "placeholder": false,
                "binaries": [
                    {{ "target_triple": "aarch64-apple-darwin", "sha256": "{REAL_HASH_OF_HELLO_WORLD}" }}
                ]
            }}"#
        ),
    );
    let assert = cmd()
        .args([
            "--pinned",
            pinned.to_str().unwrap(),
            "--binary",
            bin.to_str().unwrap(),
            "--target-triple",
            "x86_64-unknown-linux-gnu",
        ])
        .assert()
        .failure()
        .stderr(contains(
            "no entry for target_triple=x86_64-unknown-linux-gnu",
        ));
    assert_eq!(assert.get_output().status.code(), Some(65));
}

#[test]
fn allow_local_dev_downgrades_soft_failures() {
    // Hash mismatch with --allow-local-dev still succeeds, but prints a
    // WARNING and an "ok-dev" line. Verifies the dev-bypass path does not
    // accidentally silently pass; the WARNING must be visible.
    let dir = tempfile::tempdir().unwrap();
    let bin = write_binary(dir.path(), b"hello world");
    let pinned = write_pinned(
        dir.path(),
        r#"{
            "schema_version": 1,
            "upstream_commit": "abc",
            "placeholder": false,
            "binaries": [
                { "target_triple": "x86_64-unknown-linux-gnu", "sha256": "0000000000000000000000000000000000000000000000000000000000000000" }
            ]
        }"#,
    );
    cmd()
        .args([
            "--pinned",
            pinned.to_str().unwrap(),
            "--binary",
            bin.to_str().unwrap(),
            "--target-triple",
            "x86_64-unknown-linux-gnu",
            "--allow-local-dev",
        ])
        .assert()
        .success()
        .stderr(contains("WARNING (allow-local-dev)"))
        .stdout(contains("ok-dev target_triple=x86_64-unknown-linux-gnu"));
}

#[test]
fn allow_local_dev_does_not_swallow_hard_errors() {
    // Even with --allow-local-dev, IO errors must still fail. The dev-bypass
    // is for *soft* policy failures (placeholder pin, unknown triple, hash
    // mismatch), not for masking a broken invocation.
    let dir = tempfile::tempdir().unwrap();
    let pinned = write_pinned(dir.path(), r#"{ "schema_version": 1, "binaries": [] }"#);
    cmd()
        .args([
            "--pinned",
            pinned.to_str().unwrap(),
            "--binary",
            "/nonexistent/path/to/bin",
            "--target-triple",
            "x86_64-unknown-linux-gnu",
            "--allow-local-dev",
        ])
        .assert()
        .failure()
        .stderr(contains("could not read binary"));
}
