//! Live round-trip test for the macOS Secure Enclave [`KeyProvider`].
//!
//! Seals a v2 bundle with an ephemeral SEP key, then verifies it through
//! the production verifier path. Proves end-to-end that:
//!
//! 1. The bundle builder lifts `manifest_version` to 2 when the signer is
//!    a P-256 hardware key (same code path as the software P-256 provider).
//! 2. The DER signature emitted by `SecKeyCreateSignature` is the wire form
//!    `signing_ecdsa::verify_pem` accepts byte-for-byte.
//! 3. The SPKI PEM derived from `SecKeyCopyExternalRepresentation`'s 65-byte
//!    SEC1 point matches the shape the verifier already parses.
//!
//! Gated on `WITNESS_RUN_SEP_TESTS=1` because the SEP is only present on
//! Apple Silicon and T2 Macs; hosted GitHub macOS runners do not have one.
//! The SEP key is non-persistent (`kSecAttrIsPermanent=false`), which is
//! the only mode that succeeds for unsigned development binaries, and it
//! vanishes when the [`SecureEnclaveProvider`] drops at test end.

#![cfg(target_os = "macos")]

use std::path::PathBuf;

use tempfile::TempDir;
use witness_core::bundle_builder::{build_and_seal_bundle, BundleInputs, BundleSigner};
use witness_core::bundle_zip::read_bundle;
use witness_core::key_provider::KeyProvider;
use witness_core::manifest::{
    CaptureEnvironment, ConsistencyLabel, ConsistencyVerdict, Manifest, ModelFingerprint,
};
use witness_core::secure_enclave::SecureEnclaveProvider;
use witness_core::{
    verify_bundle, EvidenceKind, EvidenceReference, IncidentReport, IncidentType, KnownFingerprint,
    Location, SigningAlgorithm, WitnessCoreError,
};

struct SepBundleSigner<'a> {
    provider: &'a SecureEnclaveProvider,
}

impl<'a> BundleSigner for SepBundleSigner<'a> {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, WitnessCoreError> {
        self.provider.sign(payload)
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
        reasoning_trace_bytes: b"<think>verbatim SEP round-trip trace</think>".to_vec(),
        incident_report: IncidentReport {
            timestamp: "2026-05-16T01:00:00Z".to_string(),
            location: Location {
                lat: Some(37.33),
                lng: Some(-122.03),
                description: "secure-enclave round-trip fixture".to_string(),
            },
            witness_contact: None,
            incident_type: IncidentType::SafetyHazard,
            narrative_summary: "SEP-backed seal-and-verify regression input".to_string(),
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
            revision: "sep-test-revision".to_string(),
            sha256: "f".repeat(64),
        },
        capture_environment: CaptureEnvironment {
            os: "macOS".to_string(),
            hostname: None,
            app_version: "0.1.0".to_string(),
            captured_at: "2026-05-16T01:01:00Z".to_string(),
        },
        signer_public_key_pem: public_key_pem,
        signer_key_id: key_id,
        inference_parameters: None,
        amends: None,
        pinned_audio_sha256: None,
        pinned_image_sha256s: None,
    }
}

#[test]
fn sep_signed_v2_bundle_round_trips() {
    if std::env::var_os("WITNESS_RUN_SEP_TESTS").is_none() {
        eprintln!(
            "sep_signed_v2_bundle_round_trips: skipping. \
             set WITNESS_RUN_SEP_TESTS=1 to enable (requires Apple Silicon or T2)."
        );
        return;
    }

    let provider = SecureEnclaveProvider::new();
    let handle = provider
        .load_or_create_public()
        .expect("SEP key generation must succeed on Apple Silicon");
    assert_eq!(handle.algorithm, SigningAlgorithm::EcdsaP256);

    let signer = SepBundleSigner { provider: &provider };
    let inputs = make_inputs(handle.public_key_pem.clone(), handle.key_id.clone());
    let known: Vec<KnownFingerprint> = vec![inputs.model_fingerprint.clone().into()];

    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("sep-roundtrip.witness");
    build_and_seal_bundle(&inputs, &signer, &bundle).expect("seal SEP-signed bundle");

    let entries = read_bundle(&bundle).unwrap();
    let manifest_bytes = entries
        .get("manifest.json")
        .expect("manifest.json present in SEP-signed bundle");
    let manifest: Manifest = serde_json::from_slice(manifest_bytes).unwrap();
    assert_eq!(
        manifest.manifest_version, 2,
        "an SEP signer is ECDSA P-256, which forces manifest_version=2"
    );
    assert_eq!(
        manifest.signer.algorithm, "ecdsa-p256",
        "signer.algorithm must report the wire-level algorithm string"
    );
    assert_eq!(
        manifest.signer.key_id, handle.key_id,
        "signer.key_id must match the SEP-derived SHA-256 of the SEC1 point"
    );

    let report = verify_bundle(&bundle, &known).expect("verify SEP-signed bundle");
    assert!(
        report.is_ok(),
        "freshly SEP-signed bundle must verify cleanly: {report:?}"
    );

    // Attestation is informational. On an unsigned dev binary the SIK is
    // unreachable and we expect None; in a notarized build carrying the
    // `com.apple.security.attestation.access` entitlement this will be
    // Some("apple-sep-v1"). Either path is valid; the bundle still verifies.
    let attestation_present = manifest.signer.attestation.is_some();
    eprintln!(
        "sep_signed_v2_bundle_round_trips: signer.attestation present = {attestation_present}"
    );
    if let Some(att) = manifest.signer.attestation.as_ref() {
        assert_eq!(
            att.format, "apple-sep-v1",
            "the SEP provider must tag any attestation it produces with the apple-sep-v1 format"
        );
        assert!(
            !att.payload_b64.is_empty(),
            "attestation payload must not be empty when the provider returns Some"
        );
    }
}
