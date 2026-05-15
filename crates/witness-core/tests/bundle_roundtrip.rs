//! Sign, verify, then tamper at the asset layer and assert verification
//! fails at the asset hash step (not at the signature step).

use std::path::PathBuf;

use base64::Engine;
use ed25519_dalek::Signer;
use tempfile::TempDir;
use witness_core::bundle_builder::{build_and_seal_bundle, paths, BundleInputs};
use witness_core::bundle_zip::{read_bundle, write_bundle, ZipEntry};
use witness_core::manifest::{
    CaptureEnvironment, ConsistencyLabel, ConsistencyVerdict, Manifest, ModelFingerprint,
    SignatureDocument,
};
use witness_core::signing::{encode_public_key_pem, generate_signing_key, key_id};
use witness_core::{
    verify_bundle, BundleSigner, EvidenceKind, EvidenceReference, IncidentReport, IncidentType,
    Location, WitnessCoreError,
};

struct EphemeralSigner {
    key: ed25519_dalek::SigningKey,
}

impl BundleSigner for EphemeralSigner {
    fn sign(&self, payload: &[u8]) -> Result<[u8; 64], WitnessCoreError> {
        Ok(self.key.sign(payload).to_bytes())
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
            timestamp: "2026-05-10T22:00:00Z".to_string(),
            location: Location {
                lat: Some(39.7),
                lng: Some(-105.0),
                description: "Lakewood demo capture site".to_string(),
            },
            witness_contact: None,
            incident_type: IncidentType::SafetyHazard,
            narrative_summary: "Round-trip integration test for witness-core bundle pipeline."
                .to_string(),
            severity: 3,
            notes: None,
            evidence_references: vec![EvidenceReference {
                kind: EvidenceKind::Audio,
                sha256: "0".repeat(64),
            }],
        },
        consistency: ConsistencyVerdict {
            verdict: ConsistencyLabel::Consistent,
            summary: Some("audio narration aligns with the photographed scene".to_string()),
        },
        model_fingerprint: ModelFingerprint {
            model_id: "mlx-community/gemma-4-e4b-it-4bit".to_string(),
            revision: "test-revision".to_string(),
            sha256: "f".repeat(64),
        },
        capture_environment: CaptureEnvironment {
            os: "macOS".to_string(),
            hostname: Some("test-host".to_string()),
            app_version: "0.1.0".to_string(),
            captured_at: "2026-05-10T22:01:00Z".to_string(),
        },
        signer_public_key_pem: public_key_pem,
        signer_key_id: key_id,
        inference_parameters: None,
    }
}

fn sign_and_seal(out: &std::path::Path) -> (Vec<String>, ed25519_dalek::SigningKey) {
    let signing_key = generate_signing_key();
    let verifying = signing_key.verifying_key();
    let pem = encode_public_key_pem(&verifying).expect("pem");
    let kid = key_id(&verifying);
    let signer = EphemeralSigner {
        key: signing_key.clone(),
    };
    let inputs = make_inputs(pem, kid);
    build_and_seal_bundle(&inputs, &signer, out).expect("seal");
    (vec![inputs.model_fingerprint.sha256.clone()], signing_key)
}

#[test]
fn fresh_bundle_round_trip_verifies() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("incident.witness");
    let (known, _key) = sign_and_seal(&bundle);
    let report = verify_bundle(&bundle, &known).expect("verify");
    assert!(report.is_ok(), "expected clean verify, got {report:?}");
}

#[test]
fn rejects_bundle_after_audio_byte_modification() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("incident.witness");
    let (known, _key) = sign_and_seal(&bundle);

    let mut entries = read_bundle(&bundle).unwrap();
    let audio = entries.get_mut(paths::AUDIO).expect("audio entry");
    audio[0] ^= 0x01;
    let zipped: Vec<ZipEntry> = entries
        .into_iter()
        .map(|(path, data)| ZipEntry { path, data })
        .collect();
    write_bundle(&bundle, &zipped).unwrap();

    let report = verify_bundle(&bundle, &known).expect("verify");
    assert!(report.manifest_parsed);
    assert!(
        report.signature_valid,
        "signature should remain valid; only the asset changed"
    );
    assert!(!report.assets_untampered, "asset hash must fail");
    assert!(report
        .details
        .iter()
        .any(|d| d.contains(paths::AUDIO) && d.contains("hash mismatch")));
}

#[test]
fn rejects_bundle_after_manifest_byte_modification() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("incident.witness");
    let (known, _key) = sign_and_seal(&bundle);

    let mut entries = read_bundle(&bundle).unwrap();
    let manifest_bytes = entries.get_mut("manifest.json").unwrap();
    let mut parsed: Manifest = serde_json::from_slice(manifest_bytes).unwrap();
    parsed.bundle_id = uuid::Uuid::new_v4().to_string();
    *manifest_bytes = serde_json::to_vec(&parsed).unwrap();
    let zipped: Vec<ZipEntry> = entries
        .into_iter()
        .map(|(path, data)| ZipEntry { path, data })
        .collect();
    write_bundle(&bundle, &zipped).unwrap();

    let report = verify_bundle(&bundle, &known).expect("verify");
    assert!(
        !report.signature_valid,
        "signature must fail after manifest mutation"
    );
}

#[test]
fn rejects_bundle_after_signature_pubkey_swap() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("incident.witness");
    let (known, _key) = sign_and_seal(&bundle);

    let other_key = generate_signing_key();
    let other_pem = encode_public_key_pem(&other_key.verifying_key()).unwrap();
    let other_kid = key_id(&other_key.verifying_key());

    let mut entries = read_bundle(&bundle).unwrap();
    let manifest_bytes = entries.get_mut("manifest.json").unwrap();
    let mut parsed: Manifest = serde_json::from_slice(manifest_bytes).unwrap();
    parsed.signer.public_key_pem = other_pem.clone();
    parsed.signer.key_id = other_kid.clone();
    *manifest_bytes = serde_json::to_vec(&parsed).unwrap();
    let pem_bytes = entries
        .get_mut("public_key.pem")
        .expect("public_key.pem entry");
    *pem_bytes = other_pem.into_bytes();
    let zipped: Vec<ZipEntry> = entries
        .into_iter()
        .map(|(path, data)| ZipEntry { path, data })
        .collect();
    write_bundle(&bundle, &zipped).unwrap();

    let report = verify_bundle(&bundle, &known).expect("verify");
    assert!(
        !report.signature_valid,
        "signature must fail under a foreign key"
    );
}

#[test]
fn rejects_bundle_after_model_fingerprint_change() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("incident.witness");
    let (_known_original, _key) = sign_and_seal(&bundle);
    let new_known = vec!["a".repeat(64)];
    let report = verify_bundle(&bundle, &new_known).expect("verify");
    assert!(
        !report.model_fingerprint_known,
        "fingerprint check must fail when the bundle's fingerprint is not on the list"
    );
}

#[test]
fn signature_doc_is_well_formed() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("incident.witness");
    sign_and_seal(&bundle);
    let entries = read_bundle(&bundle).unwrap();
    let sig: SignatureDocument =
        serde_json::from_slice(entries.get("signature.json").unwrap()).unwrap();
    assert_eq!(sig.algorithm, "ed25519");
    assert_eq!(sig.signed_payload, "manifest.json");
    assert_eq!(sig.canonicalization, "rfc8785");
    let raw = base64::engine::general_purpose::STANDARD
        .decode(sig.signature_b64.as_bytes())
        .unwrap();
    assert_eq!(raw.len(), 64);
}
