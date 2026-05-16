//! Regression tests for manifest_version routing.
//!
//! The seal path still emits v1 today, so to exercise v2 we seal a v1 bundle,
//! mutate the in-zip manifest to v2 (or to a malformed mix-and-match shape),
//! re-canonicalize, re-sign with the same Ed25519 key, and repack. The
//! verifier must:
//! - accept a v2 manifest that uses Ed25519 with no attestation
//! - accept a v2 manifest that uses Ed25519 with an attestation blob (the
//!   field is informational at this verifier version)
//! - reject a v2 manifest declaring `ecdsa-p256` with a "not yet implemented"
//!   detail rather than mis-verifying or panicking
//! - reject a v1 manifest that carries an attestation blob (v2-only field)
//! - reject a v1 manifest that declares `ecdsa-p256` (permitted set per
//!   version is enforced at the verifier, not only at the schema)

use std::path::PathBuf;

use base64::Engine;
use ed25519_dalek::Signer;
use tempfile::TempDir;
use witness_core::bundle_builder::{build_and_seal_bundle, BundleInputs};
use witness_core::bundle_zip::{read_bundle, write_bundle, ZipEntry};
use witness_core::canonical::canonicalize;
use witness_core::manifest::{
    CaptureEnvironment, ConsistencyLabel, ConsistencyVerdict, Manifest, ModelFingerprint,
    SignatureDocument, SignerAttestation,
};
use witness_core::signing::{encode_public_key_pem, generate_signing_key, key_id};
use witness_core::{
    verify_bundle, BundleSigner, EvidenceKind, EvidenceReference, IncidentReport, IncidentType,
    KnownFingerprint, Location, WitnessCoreError,
};

struct EphemeralSigner {
    key: ed25519_dalek::SigningKey,
}

impl BundleSigner for EphemeralSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, WitnessCoreError> {
        Ok(self.key.sign(payload).to_bytes().to_vec())
    }
    fn algorithm(&self) -> witness_core::SigningAlgorithm {
        witness_core::SigningAlgorithm::Ed25519
    }
}

fn fixture_audio() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../tests/fixtures/day-3-scenarios/1/audio.wav");
    p
}

fn fixture_image() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../tests/fixtures/day-3-scenarios/1/image1.jpg");
    p
}

fn make_inputs(public_key_pem: String, key_id: String) -> BundleInputs {
    BundleInputs {
        audio_path: fixture_audio(),
        image_paths: vec![fixture_image()],
        reasoning_trace_bytes: b"<think>verbatim thinking trace</think>".to_vec(),
        incident_report: IncidentReport {
            timestamp: "2026-05-15T22:00:00Z".to_string(),
            location: Location {
                lat: Some(39.7),
                lng: Some(-105.0),
                description: "manifest v2 routing fixture".to_string(),
            },
            witness_contact: None,
            incident_type: IncidentType::SafetyHazard,
            narrative_summary: "v2 manifest routing regression input".to_string(),
            severity: 2,
            notes: None,
            evidence_references: vec![EvidenceReference {
                kind: EvidenceKind::Audio,
                sha256: "0".repeat(64),
            }],
        },
        consistency: ConsistencyVerdict {
            verdict: ConsistencyLabel::Consistent,
            summary: None,
        },
        model_fingerprint: ModelFingerprint {
            model_id: "mlx-community/gemma-4-e4b-it-4bit".to_string(),
            revision: "test-revision".to_string(),
            sha256: "f".repeat(64),
        },
        capture_environment: CaptureEnvironment {
            os: "macOS".to_string(),
            hostname: None,
            app_version: "0.1.0".to_string(),
            captured_at: "2026-05-15T22:01:00Z".to_string(),
        },
        signer_public_key_pem: public_key_pem,
        signer_key_id: key_id,
        inference_parameters: None,
        amends: None,
        pinned_audio_sha256: None,
        pinned_image_sha256s: None,
    }
}

/// Seal a v1 bundle, then call `mutate` on the in-zip manifest, re-sign the
/// canonicalized bytes with `signing_key`, write the updated `signature.json`
/// alongside, and repack. The verifier reads the resulting bundle as if it had
/// always been the mutated shape.
fn seal_and_mutate<F>(
    out: &std::path::Path,
    mutate: F,
) -> (Vec<KnownFingerprint>, ed25519_dalek::SigningKey)
where
    F: FnOnce(&mut Manifest),
{
    let signing_key = generate_signing_key();
    let verifying = signing_key.verifying_key();
    let pem = encode_public_key_pem(&verifying).expect("pem");
    let kid = key_id(&verifying);
    let signer = EphemeralSigner {
        key: signing_key.clone(),
    };
    let inputs = make_inputs(pem, kid.clone());
    let known = vec![inputs.model_fingerprint.clone().into()];
    build_and_seal_bundle(&inputs, &signer, out).expect("seal v1 baseline");

    let mut entries = read_bundle(out).unwrap();
    let manifest_bytes = entries.get_mut("manifest.json").unwrap();
    let mut manifest: Manifest = serde_json::from_slice(manifest_bytes).unwrap();
    mutate(&mut manifest);
    let canonical = canonicalize(&manifest).expect("re-canonicalize after mutation");
    *manifest_bytes = canonical.clone();

    let sig_bytes = entries.get_mut("signature.json").unwrap();
    let mut sig_doc: SignatureDocument = serde_json::from_slice(sig_bytes).unwrap();
    let new_signature = signing_key.sign(&canonical);
    sig_doc.signature_b64 =
        base64::engine::general_purpose::STANDARD.encode(new_signature.to_bytes());
    sig_doc.algorithm = manifest.signer.algorithm.clone();
    sig_doc.key_id = manifest.signer.key_id.clone();
    *sig_bytes = serde_json::to_vec(&sig_doc).unwrap();

    let zipped: Vec<ZipEntry> = entries
        .into_iter()
        .map(|(path, data)| ZipEntry { path, data })
        .collect();
    write_bundle(out, &zipped).unwrap();
    (known, signing_key)
}

#[test]
fn v2_bundle_with_ed25519_verifies() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("v2-ed25519.witness");
    let (known, _key) = seal_and_mutate(&bundle, |m| {
        m.manifest_version = 2;
    });
    let report = verify_bundle(&bundle, &known).expect("verify");
    assert!(
        report.is_ok(),
        "v2 manifest with ed25519 must verify: {report:?}"
    );
}

#[test]
fn v2_bundle_with_ed25519_and_attestation_verifies() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("v2-ed25519-attest.witness");
    let (known, _key) = seal_and_mutate(&bundle, |m| {
        m.manifest_version = 2;
        m.signer.attestation = Some(SignerAttestation {
            format: "apple-sep-v1".to_string(),
            payload_b64: "QUFFQg==".to_string(),
            certificate_chain_b64: Some(vec!["Q0VSVA==".to_string()]),
        });
    });
    let report = verify_bundle(&bundle, &known).expect("verify");
    assert!(
        report.is_ok(),
        "v2 manifest with ed25519 + attestation must verify: {report:?}"
    );
}

#[test]
fn v2_bundle_with_algorithm_lie_fails_signature_verification() {
    // A bundle that claims signer.algorithm=ecdsa-p256 but is actually
    // signed with an Ed25519 key (and ships an Ed25519 PEM) must fail the
    // signature row. The P-256 dispatch tries to parse the PEM as a P-256
    // key and either rejects the PEM or rejects the malformed DER signature.
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("v2-algorithm-lie.witness");
    let (known, _key) = seal_and_mutate(&bundle, |m| {
        m.manifest_version = 2;
        m.signer.algorithm = "ecdsa-p256".to_string();
    });
    let report = verify_bundle(&bundle, &known).expect("verify");
    assert!(
        !report.signature_valid,
        "ecdsa-p256 claim over an Ed25519 key/signature must fail"
    );
    assert!(
        report
            .details
            .iter()
            .any(|d| d.contains("signature did not verify")),
        "detail must surface the verification failure: {:?}",
        report.details
    );
}

#[test]
fn v1_bundle_with_attestation_field_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("v1-bad-attest.witness");
    let (known, _key) = seal_and_mutate(&bundle, |m| {
        m.signer.attestation = Some(SignerAttestation {
            format: "apple-sep-v1".to_string(),
            payload_b64: "QUFFQg==".to_string(),
            certificate_chain_b64: None,
        });
    });
    let report = verify_bundle(&bundle, &known).expect("verify");
    assert!(
        !report.signature_valid,
        "v1 manifest carrying a v2-only attestation field must fail"
    );
    assert!(
        report
            .details
            .iter()
            .any(|d| d.contains("attestation") && d.contains("v1")),
        "detail must explain the v1/attestation incompatibility: {:?}",
        report.details
    );
}

#[test]
fn v1_bundle_declaring_ecdsa_p256_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("v1-ecdsa.witness");
    let (known, _key) = seal_and_mutate(&bundle, |m| {
        m.signer.algorithm = "ecdsa-p256".to_string();
    });
    let report = verify_bundle(&bundle, &known).expect("verify");
    assert!(
        !report.signature_valid,
        "v1 manifest must restrict signer.algorithm to ed25519"
    );
    assert!(
        report
            .details
            .iter()
            .any(|d| d.contains("permits only") && d.contains("ed25519")),
        "detail must name the permitted set for v1: {:?}",
        report.details
    );
}

#[test]
fn unknown_manifest_version_is_rejected_at_routing() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("v99.witness");

    let signing_key = generate_signing_key();
    let verifying = signing_key.verifying_key();
    let pem = encode_public_key_pem(&verifying).expect("pem");
    let kid = key_id(&verifying);
    let signer = EphemeralSigner {
        key: signing_key.clone(),
    };
    let inputs = make_inputs(pem, kid);
    let known: Vec<KnownFingerprint> = vec![inputs.model_fingerprint.clone().into()];
    build_and_seal_bundle(&inputs, &signer, &bundle).expect("seal");

    let mut entries = read_bundle(&bundle).unwrap();
    let manifest_bytes = entries.get_mut("manifest.json").unwrap();
    let mut manifest: Manifest = serde_json::from_slice(manifest_bytes).unwrap();
    manifest.manifest_version = 99;
    *manifest_bytes = canonicalize(&manifest).expect("canonicalize");
    let zipped: Vec<ZipEntry> = entries
        .into_iter()
        .map(|(path, data)| ZipEntry { path, data })
        .collect();
    write_bundle(&bundle, &zipped).unwrap();

    let err =
        verify_bundle(&bundle, &known).expect_err("verifier must hard-error on unknown version");
    let message = err.to_string();
    assert!(
        message.contains("manifest_version 99") && message.contains("not supported"),
        "error message must name the unknown version and the supported set: {message}"
    );
}
