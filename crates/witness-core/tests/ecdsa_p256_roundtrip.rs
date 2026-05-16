//! Round-trip tests for the ECDSA P-256 software signing path.
//!
//! Seal a manifest with a P-256 [`BundleSigner`], then verify it through the
//! same code path the JS verifier mirrors. Proves the bundle builder
//! correctly bumps `manifest_version` to 2 when the signer reports
//! ECDSA P-256, that the wire signature is the ASN.1/DER form the
//! verifier expects, and that the signature actually verifies.

use std::path::PathBuf;

use p256::ecdsa::SigningKey;
use tempfile::TempDir;
use witness_core::bundle_builder::{build_and_seal_bundle, BundleInputs, BundleSigner};
use witness_core::bundle_zip::read_bundle;
use witness_core::manifest::{
    CaptureEnvironment, ConsistencyLabel, ConsistencyVerdict, Manifest, ModelFingerprint,
    SignatureDocument,
};
use witness_core::signing_ecdsa::{encode_public_key_pem, generate_signing_key, key_id, sign};
use witness_core::{
    verify_bundle, EvidenceKind, EvidenceReference, IncidentReport, IncidentType, KnownFingerprint,
    Location, SigningAlgorithm, WitnessCoreError,
};

struct P256EphemeralSigner {
    key: SigningKey,
}

impl BundleSigner for P256EphemeralSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, WitnessCoreError> {
        Ok(sign(&self.key, payload))
    }
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::EcdsaP256
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
        reasoning_trace_bytes: b"<think>verbatim P-256 round-trip trace</think>".to_vec(),
        incident_report: IncidentReport {
            timestamp: "2026-05-15T22:00:00Z".to_string(),
            location: Location {
                lat: Some(39.7),
                lng: Some(-105.0),
                description: "ecdsa-p256 round-trip fixture".to_string(),
            },
            witness_contact: None,
            incident_type: IncidentType::SafetyHazard,
            narrative_summary: "P-256 software seal-and-verify regression input".to_string(),
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

fn seal_with_p256(out: &std::path::Path) -> Vec<KnownFingerprint> {
    let key = generate_signing_key();
    let pem = encode_public_key_pem(key.verifying_key()).expect("encode P-256 SPKI PEM");
    let kid = key_id(key.verifying_key());
    let signer = P256EphemeralSigner { key };
    let inputs = make_inputs(pem, kid);
    build_and_seal_bundle(&inputs, &signer, out).expect("seal P-256 bundle");
    vec![inputs.model_fingerprint.clone().into()]
}

#[test]
fn p256_software_bundle_round_trips() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("p256-roundtrip.witness");
    let known = seal_with_p256(&bundle);
    let report = verify_bundle(&bundle, &known).expect("verify");
    assert!(
        report.is_ok(),
        "freshly P-256-signed bundle must verify cleanly: {report:?}"
    );
}

#[test]
fn p256_seal_bumps_manifest_version_to_two() {
    // The bundle builder must lift manifest_version to 2 when the signer
    // reports ECDSA P-256: a v1 manifest cannot carry signer.algorithm=
    // "ecdsa-p256" under the published schema.
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("p256-version-bump.witness");
    let _known = seal_with_p256(&bundle);
    let entries = read_bundle(&bundle).unwrap();
    let manifest_bytes = entries.get("manifest.json").expect("manifest.json present");
    let manifest: Manifest = serde_json::from_slice(manifest_bytes).unwrap();
    assert_eq!(
        manifest.manifest_version, 2,
        "P-256 signer must produce a v2 manifest"
    );
    assert_eq!(
        manifest.signer.algorithm, "ecdsa-p256",
        "signer.algorithm must reflect the actual signer"
    );
    let sig_bytes = entries
        .get("signature.json")
        .expect("signature.json present");
    let sig_doc: SignatureDocument = serde_json::from_slice(sig_bytes).unwrap();
    assert_eq!(
        sig_doc.algorithm, "ecdsa-p256",
        "signature.json must agree with manifest.signer.algorithm"
    );
}
