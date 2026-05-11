//! Generate a clean fixture bundle for verifier end-to-end tests.
//!
//! Run this test to emit tests/fixtures/day-4-fixture.witness from the
//! workspace root. It uses the same synthetic data as bundle_roundtrip.rs.

use std::path::PathBuf;

use ed25519_dalek::Signer;
use witness_core::bundle_builder::{build_and_seal_bundle, BundleInputs};
use witness_core::manifest::{
    CaptureEnvironment, ConsistencyLabel, ConsistencyVerdict, ModelFingerprint,
};
use witness_core::signing::{encode_public_key_pem, generate_signing_key, key_id};
use witness_core::{
    BundleSigner, EvidenceKind, EvidenceReference, IncidentReport, IncidentType, Location,
    WitnessCoreError,
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

#[test]
fn generate_day_4_fixture() {
    let signing_key = generate_signing_key();
    let verifying = signing_key.verifying_key();
    let pem = encode_public_key_pem(&verifying).expect("pem");
    let kid = key_id(&verifying);
    let signer = EphemeralSigner {
        key: signing_key.clone(),
    };

    let inputs = BundleInputs {
        audio_path: fixture_audio(),
        image_paths: vec![fixture_image()],
        reasoning_trace_bytes: b"verbatim thinking trace".to_vec(),
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
            revision: "cc3b666c01c20395e0dcebd53854504c7d9821f9".to_string(),
            sha256: "339409bd18494955556e1fde6ccc15faaa9f707b911b74791fe290b9d722beed".to_string(),
        },
        capture_environment: CaptureEnvironment {
            os: "macOS".to_string(),
            hostname: Some("test-host".to_string()),
            app_version: "0.1.0".to_string(),
            captured_at: "2026-05-10T22:01:00Z".to_string(),
        },
        signer_public_key_pem: pem,
        signer_key_id: kid,
    };

    let mut out = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    out.push("../../tests/fixtures/day-4-fixture.witness");
    let bundle_id = build_and_seal_bundle(&inputs, &signer, &out).expect("seal");
    println!("Fixture written: {out:?} bundle_id={bundle_id}");
}
