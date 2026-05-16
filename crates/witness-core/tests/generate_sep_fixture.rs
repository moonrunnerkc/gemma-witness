//! Bake the WS3-8 Secure Enclave fixture bundle.
//!
//! Run on an Apple Silicon (or T2) host with:
//!
//! ```text
//! WITNESS_RUN_SEP_TESTS=1 WITNESS_WRITE_SEP_FIXTURE=1 \
//!   cargo test -p witness-core --features hardware-keys --test generate_sep_fixture \
//!   -- --nocapture
//! ```
//!
//! Produces `tests/fixtures/secure-enclave-fixture.witness` containing a v2
//! manifest signed by an ephemeral, non-persistent SEP key. The bundle also
//! carries a deterministic `signer.attestation` blob whose
//! `format = "apple-sep-v1-fixture"` makes the test provenance explicit:
//! the bytes are a stand-in for what a notarized build with the
//! `com.apple.security.attestation.access` entitlement would emit. Real
//! `apple-sep-v1` payloads are produced by Apple's SIK + GID and are not
//! reachable from an unsigned dev binary; the fixture demonstrates the
//! shape of the wire surface the verifier renders.
//!
//! The signer key is unique to the host that generates the bundle: every
//! re-bake produces a fresh public key. Regression tests verify the
//! committed bytes; do not regenerate unless the schema changes.

#![cfg(target_os = "macos")]

use std::path::PathBuf;

use witness_core::bundle_builder::{build_and_seal_bundle, BundleInputs, BundleSigner};
use witness_core::key_provider::KeyProvider;
use witness_core::manifest::{
    CaptureEnvironment, ConsistencyLabel, ConsistencyVerdict, ModelFingerprint, SignerAttestation,
};
use witness_core::secure_enclave::SecureEnclaveProvider;
use witness_core::{
    EvidenceKind, EvidenceReference, IncidentReport, IncidentType, Location, SigningAlgorithm,
    WitnessCoreError,
};

/// Format tag used on the fixture's `signer.attestation.format` field.
///
/// Distinct from production `apple-sep-v1` so a reader cannot mistake the
/// fixture's deterministic bytes for a real SEP attestation document.
const FIXTURE_ATTESTATION_FORMAT: &str = "apple-sep-v1-fixture";
/// Fixed payload (literal ASCII "secure-enclave-witness-fixture") so the
/// committed bundle's `signer.attestation.payload_b64` stays reviewable in
/// plaintext rather than appearing as opaque random bytes.
const FIXTURE_ATTESTATION_PAYLOAD: &[u8] = b"secure-enclave-witness-fixture";

struct FixtureSigner<'a> {
    inner: &'a SecureEnclaveProvider,
}

impl<'a> BundleSigner for FixtureSigner<'a> {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, WitnessCoreError> {
        self.inner.sign(payload)
    }
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::EcdsaP256
    }
    fn attestation(&self) -> Option<SignerAttestation> {
        use base64::Engine as _;
        Some(SignerAttestation {
            format: FIXTURE_ATTESTATION_FORMAT.to_string(),
            payload_b64: base64::engine::general_purpose::STANDARD
                .encode(FIXTURE_ATTESTATION_PAYLOAD),
            certificate_chain_b64: None,
        })
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
fn generate_secure_enclave_fixture() {
    if std::env::var_os("WITNESS_RUN_SEP_TESTS").is_none()
        || std::env::var_os("WITNESS_WRITE_SEP_FIXTURE").is_none()
    {
        eprintln!(
            "generate_secure_enclave_fixture: skipping. \
             set both WITNESS_RUN_SEP_TESTS=1 AND WITNESS_WRITE_SEP_FIXTURE=1 \
             to write tests/fixtures/secure-enclave-fixture.witness."
        );
        return;
    }

    let provider = SecureEnclaveProvider::new();
    let handle = provider
        .load_or_create_public()
        .expect("SEP key generation must succeed on Apple Silicon");
    assert_eq!(handle.algorithm, SigningAlgorithm::EcdsaP256);

    let signer = FixtureSigner { inner: &provider };
    let inputs = BundleInputs {
        audio_path: fixture_audio(),
        image_paths: vec![fixture_image()],
        reasoning_trace_bytes: b"<think>verbatim trace for the SEP fixture</think>".to_vec(),
        incident_report: IncidentReport {
            timestamp: "2026-05-16T02:00:00Z".to_string(),
            location: Location {
                lat: Some(37.33),
                lng: Some(-122.03),
                description: "WS3-8 SEP fixture capture".to_string(),
            },
            witness_contact: None,
            incident_type: IncidentType::SafetyHazard,
            narrative_summary: "Fixture: SEP-signed v2 bundle with apple-sep-v1-fixture \
                                attestation. Used by the regression tests in \
                                witness-core::secure_enclave_fixture and the JS verifier."
                .to_string(),
            severity: 2,
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
            captured_at: "2026-05-16T02:01:00Z".to_string(),
        },
        signer_public_key_pem: handle.public_key_pem,
        signer_key_id: handle.key_id,
        inference_parameters: None,
        amends: None,
        pinned_audio_sha256: None,
        pinned_image_sha256s: None,
    };

    let mut out = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    out.push("../../tests/fixtures/secure-enclave-fixture.witness");
    let bundle_id = build_and_seal_bundle(&inputs, &signer, &out).expect("seal SEP fixture");
    println!(
        "wrote SEP fixture to {out:?} bundle_id={bundle_id} \
         signer.algorithm=ecdsa-p256 attestation.format={FIXTURE_ATTESTATION_FORMAT}"
    );
}
