//! Regression test for the committed WS3-8 Secure Enclave fixture.
//!
//! Loads `tests/fixtures/secure-enclave-fixture.witness` from disk and
//! confirms:
//!
//! 1. The bundle parses as a v2 manifest.
//! 2. `signer.algorithm == "ecdsa-p256"`.
//! 3. `signer.attestation` is present with the fixture-tagged format.
//! 4. The Rust verifier reports `is_ok()` against a model-fingerprint
//!    allowlist that includes the bundle's pinned entry.
//!
//! Runs in the default workspace test suite: it never invokes the SEP,
//! it just reads bytes off disk. The committed bundle was baked by
//! `generate_sep_fixture.rs` on an Apple Silicon host; the signer's
//! public key is captured inside the bundle so any host can verify.

use std::path::PathBuf;

use witness_core::bundle_zip::read_bundle;
use witness_core::manifest::Manifest;
use witness_core::{verify_bundle, KnownFingerprint, ModelFingerprint};

fn fixture_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../tests/fixtures/secure-enclave-fixture.witness");
    p
}

#[test]
fn sep_fixture_is_a_v2_ecdsa_p256_bundle_with_attestation() {
    let entries = read_bundle(&fixture_path()).expect("read SEP fixture");
    let manifest_bytes = entries
        .get("manifest.json")
        .expect("manifest.json present in SEP fixture");
    let manifest: Manifest = serde_json::from_slice(manifest_bytes).expect("parse manifest");

    assert_eq!(
        manifest.manifest_version, 2,
        "SEP fixture must be v2: ecdsa-p256 is only permitted from manifest_version=2"
    );
    assert_eq!(
        manifest.signer.algorithm, "ecdsa-p256",
        "SEP fixture must carry ecdsa-p256 as the signer algorithm"
    );
    let attestation = manifest
        .signer
        .attestation
        .as_ref()
        .expect("SEP fixture must carry signer.attestation");
    assert_eq!(
        attestation.format, "apple-sep-v1-fixture",
        "fixture attestation must use the apple-sep-v1-fixture tag to keep it \
         distinguishable from a production apple-sep-v1 payload"
    );
    assert!(
        !attestation.payload_b64.is_empty(),
        "fixture attestation payload_b64 must not be empty"
    );
}

#[test]
fn sep_fixture_verifies_against_the_pinned_model_fingerprint() {
    let entries = read_bundle(&fixture_path()).expect("read SEP fixture");
    let manifest_bytes = entries
        .get("manifest.json")
        .expect("manifest.json present in SEP fixture");
    let manifest: Manifest = serde_json::from_slice(manifest_bytes).expect("parse manifest");

    let known: Vec<KnownFingerprint> = vec![ModelFingerprint {
        model_id: manifest.assertions.model_fingerprint.model_id.clone(),
        revision: manifest.assertions.model_fingerprint.revision.clone(),
        sha256: manifest.assertions.model_fingerprint.sha256.clone(),
    }
    .into()];

    let report = verify_bundle(&fixture_path(), &known).expect("verify SEP fixture");
    assert!(
        report.is_ok(),
        "committed SEP fixture must verify cleanly via the Rust verifier: {report:?}"
    );
}
