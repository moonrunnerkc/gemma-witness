//! Regression coverage for the registry envelope tamper paths.
//!
//! The `verify_consistency_*` unit tests in `src/lib.rs` cover the
//! function in isolation. These integration tests exercise the
//! `enforce_for_build` entry point that `crates/witness-fingerprints/build.rs`
//! and the verifier-side build call into, and they walk a tampered tree
//! through that entry point exactly as a build would.
//!
//! Note: signature-tamper regression (corrupting `registry-manifest.sigstore`
//! and asserting verify_signature rejects) is intentionally not in this
//! file. The first real cosign bundle does not exist on `main` until the
//! signing workflow runs once, at which point we can capture a fixture
//! and add the signature-tamper case. The placeholder-rejection path in
//! `src/signature.rs::placeholder_envelope_is_refused_by_signature_gate`
//! covers the signature-gate "fail closed" property today.

use std::fs;
use tempfile::TempDir;
use witness_fingerprint_verify::{
    REGISTRY_MANIFEST_FILENAME, canonical_bytes, compute_manifest, enforce_for_build,
    VerifyError,
};

fn seed_registry(dir: &std::path::Path) {
    fs::write(dir.join("alpha.json"), b"{\"alpha\":1}").expect("write alpha");
    fs::write(dir.join("beta.json"), b"{\"beta\":2}").expect("write beta");
}

fn seed_envelope(dir: &std::path::Path) {
    let manifest = compute_manifest(dir).expect("compute");
    let bytes = canonical_bytes(&manifest).expect("canon");
    fs::write(dir.join(REGISTRY_MANIFEST_FILENAME), bytes).expect("write envelope");
}

#[test]
fn enforce_for_build_passes_on_a_fresh_placeholder_envelope() {
    let dir = TempDir::new().expect("tempdir");
    seed_registry(dir.path());
    seed_envelope(dir.path());
    let placeholder = enforce_for_build(dir.path()).expect("must pass");
    assert!(placeholder, "freshly recomputed envelope must be a placeholder");
}

#[test]
fn enforce_for_build_rejects_a_tampered_fingerprint_file() {
    let dir = TempDir::new().expect("tempdir");
    seed_registry(dir.path());
    seed_envelope(dir.path());
    // The envelope was just computed; tampering with one of the
    // fingerprint files after the fact must trip the content gate.
    fs::write(dir.path().join("alpha.json"), b"{\"alpha\":\"tampered\"}")
        .expect("tamper alpha");
    let err = enforce_for_build(dir.path()).expect_err("must fail");
    assert!(
        matches!(err, VerifyError::HashMismatch { .. }),
        "expected HashMismatch, got {err:?}"
    );
    let detail = format!("{err}");
    assert!(
        detail.contains("alpha.json"),
        "error must name the tampered file; got: {detail}"
    );
}

#[test]
fn enforce_for_build_rejects_a_new_file_added_after_signing() {
    let dir = TempDir::new().expect("tempdir");
    seed_registry(dir.path());
    seed_envelope(dir.path());
    fs::write(dir.path().join("gamma.json"), b"{\"gamma\":3}")
        .expect("drop in a new file after signing");
    let err = enforce_for_build(dir.path()).expect_err("must fail");
    assert!(
        matches!(
            err,
            VerifyError::CoverageCountMismatch { .. } | VerifyError::UncoveredFile { .. }
        ),
        "expected coverage gate to flag the new file, got {err:?}"
    );
}

#[test]
fn enforce_for_build_rejects_a_removed_file() {
    let dir = TempDir::new().expect("tempdir");
    seed_registry(dir.path());
    seed_envelope(dir.path());
    fs::remove_file(dir.path().join("beta.json")).expect("remove beta");
    let err = enforce_for_build(dir.path()).expect_err("must fail");
    assert!(
        matches!(
            err,
            VerifyError::CoverageCountMismatch { .. } | VerifyError::MissingFile { .. }
        ),
        "expected coverage gate to flag the missing file, got {err:?}"
    );
}

#[test]
fn enforce_for_build_rejects_a_truncated_envelope() {
    let dir = TempDir::new().expect("tempdir");
    seed_registry(dir.path());
    seed_envelope(dir.path());
    fs::write(dir.path().join(REGISTRY_MANIFEST_FILENAME), b"{")
        .expect("truncate envelope");
    let err = enforce_for_build(dir.path()).expect_err("must fail");
    assert!(
        matches!(err, VerifyError::ManifestParse { .. }),
        "expected ManifestParse, got {err:?}"
    );
}
