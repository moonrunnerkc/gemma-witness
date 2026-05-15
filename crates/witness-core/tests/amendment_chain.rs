//! Seal an original bundle, derive its amendment, verify both.
//!
//! The amendment carries the original's bundle_id plus the SHA-256 of the
//! original's JCS-canonicalized manifest. A reviewer who has both files can
//! confirm the amendment refers to the specific manifest bytes that were
//! signed, not a parallel claim.

use std::path::PathBuf;

use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use witness_core::bundle_builder::{build_and_seal_bundle, paths, BundleInputs};
use witness_core::bundle_zip::read_bundle;
use witness_core::canonical::canonicalize;
use witness_core::manifest::{
    AmendsReference, CaptureEnvironment, ConsistencyLabel, ConsistencyVerdict, Manifest,
    ModelFingerprint,
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

fn fingerprint() -> ModelFingerprint {
    ModelFingerprint {
        model_id: "mlx-community/gemma-4-e4b-it-4bit".to_string(),
        revision: "amendment-chain-test".to_string(),
        sha256: "f".repeat(64),
    }
}

fn report(summary: &str) -> IncidentReport {
    IncidentReport {
        timestamp: "2026-05-12T18:00:00Z".to_string(),
        location: Location {
            lat: None,
            lng: None,
            description: "amendment-chain test site".to_string(),
        },
        witness_contact: None,
        incident_type: IncidentType::SafetyHazard,
        narrative_summary: summary.to_string(),
        severity: 2,
        notes: None,
        evidence_references: vec![EvidenceReference {
            kind: EvidenceKind::Audio,
            sha256: "0".repeat(64),
        }],
    }
}

fn make_inputs(
    pem: String,
    kid: String,
    summary: &str,
    amends: Option<AmendsReference>,
) -> BundleInputs {
    BundleInputs {
        audio_path: fixture_audio(),
        image_paths: vec![fixture_image()],
        reasoning_trace_bytes: b"verbatim trace for amendment-chain test".to_vec(),
        incident_report: report(summary),
        consistency: ConsistencyVerdict {
            verdict: ConsistencyLabel::Consistent,
            summary: Some("aligned".to_string()),
        },
        model_fingerprint: fingerprint(),
        capture_environment: CaptureEnvironment {
            os: "macOS".to_string(),
            hostname: Some("test".to_string()),
            app_version: "0.1.0-amendment-test".to_string(),
            captured_at: "2026-05-12T18:01:00Z".to_string(),
        },
        signer_public_key_pem: pem,
        signer_key_id: kid,
        inference_parameters: None,
        amends,
        pinned_audio_sha256: None,
        pinned_image_sha256s: None,
    }
}

#[test]
fn amendment_references_original_manifest_sha_and_both_verify() {
    let tmp = TempDir::new().expect("tmpdir");
    let original_path = tmp.path().join("original.witness");
    let amendment_path = tmp.path().join("amendment.witness");

    let signing_key = generate_signing_key();
    let verifying = signing_key.verifying_key();
    let pem = encode_public_key_pem(&verifying).expect("pem");
    let kid = key_id(&verifying);
    let signer = EphemeralSigner {
        key: signing_key.clone(),
    };

    let original_inputs = make_inputs(
        pem.clone(),
        kid.clone(),
        "original report. claims the truck was at oak and main.",
        None,
    );
    let original_bundle_id =
        build_and_seal_bundle(&original_inputs, &signer, &original_path).expect("seal original");

    let entries = read_bundle(&original_path).expect("read original");
    let manifest_bytes = entries
        .get(paths::MANIFEST)
        .expect("original manifest entry");
    let original_manifest: Manifest =
        serde_json::from_slice(manifest_bytes).expect("parse original manifest");
    let canonical = canonicalize(&original_manifest).expect("canonicalize original manifest");
    let original_manifest_sha256 = hex::encode(Sha256::digest(&canonical));

    let amendment_inputs = make_inputs(
        pem,
        kid.clone(),
        "amendment. the intersection was oak and seventh, not oak and main.",
        Some(AmendsReference {
            original_bundle_id: original_bundle_id.clone(),
            original_manifest_sha256: original_manifest_sha256.clone(),
            original_signer_key_id: kid.clone(),
            reason: "wrong cross-street; correcting before the editor publishes".to_string(),
        }),
    );
    build_and_seal_bundle(&amendment_inputs, &signer, &amendment_path).expect("seal amendment");

    let known: Vec<witness_core::KnownFingerprint> = vec![fingerprint().into()];

    let original_report = verify_bundle(&original_path, &known).expect("verify original");
    assert!(
        original_report.is_ok(),
        "original must verify clean: {original_report:?}"
    );

    let amendment_report = verify_bundle(&amendment_path, &known).expect("verify amendment");
    assert!(
        amendment_report.is_ok(),
        "amendment must verify clean: {amendment_report:?}"
    );

    let amendment_entries = read_bundle(&amendment_path).expect("read amendment");
    let amendment_manifest: Manifest =
        serde_json::from_slice(amendment_entries.get(paths::MANIFEST).expect("manifest"))
            .expect("parse amendment manifest");
    let amends = amendment_manifest
        .amends
        .expect("amendment manifest must carry an amends field");
    assert_eq!(amends.original_bundle_id, original_bundle_id);
    assert_eq!(amends.original_manifest_sha256, original_manifest_sha256);
    assert_eq!(amends.original_signer_key_id, kid);
}

#[test]
fn amendment_signed_by_different_key_fails_chain_verification() {
    let tmp = TempDir::new().expect("tmpdir");
    let original_path = tmp.path().join("original.witness");
    let amendment_path = tmp.path().join("amendment.witness");

    let original_key = generate_signing_key();
    let original_verifying = original_key.verifying_key();
    let original_pem = encode_public_key_pem(&original_verifying).expect("pem");
    let original_kid = key_id(&original_verifying);
    let original_signer = EphemeralSigner {
        key: original_key.clone(),
    };

    let original_inputs = make_inputs(
        original_pem.clone(),
        original_kid.clone(),
        "original report",
        None,
    );
    let original_bundle_id =
        build_and_seal_bundle(&original_inputs, &original_signer, &original_path)
            .expect("seal original");

    let entries = read_bundle(&original_path).expect("read original");
    let manifest_bytes = entries
        .get(paths::MANIFEST)
        .expect("original manifest entry");
    let original_manifest: Manifest =
        serde_json::from_slice(manifest_bytes).expect("parse original manifest");
    let canonical = canonicalize(&original_manifest).expect("canonicalize original manifest");
    let original_manifest_sha256 = hex::encode(Sha256::digest(&canonical));

    // Attacker keypair, not the original signer.
    let attacker_key = generate_signing_key();
    let attacker_verifying = attacker_key.verifying_key();
    let attacker_pem = encode_public_key_pem(&attacker_verifying).expect("attacker pem");
    let attacker_kid = key_id(&attacker_verifying);
    let attacker_signer = EphemeralSigner { key: attacker_key };

    // The attacker forges an "amendment" referencing the real original but
    // signed with their own key. The amends back-link still names the real
    // original signer, because that is the only value the attacker would
    // pick (anything else immediately tells a verifier the chain is broken).
    let attacker_amendment_inputs = make_inputs(
        attacker_pem,
        attacker_kid.clone(),
        "attacker amendment claiming the original was fabricated",
        Some(AmendsReference {
            original_bundle_id: original_bundle_id.clone(),
            original_manifest_sha256: original_manifest_sha256.clone(),
            original_signer_key_id: original_kid.clone(),
            reason: "attacker forging an amendment they did not sign".to_string(),
        }),
    );
    build_and_seal_bundle(
        &attacker_amendment_inputs,
        &attacker_signer,
        &amendment_path,
    )
    .expect("attacker seal succeeds: individual bundle is self-consistent");

    let known: Vec<witness_core::KnownFingerprint> = vec![fingerprint().into()];

    let amendment_report =
        witness_core::verify_amendment_chain(&amendment_path, &known).expect("verify chain");
    assert!(
        !amendment_report.is_ok(),
        "amendment signed by attacker_kid={attacker_kid} but back-linked to original_kid={original_kid} must NOT pass chain verification: {amendment_report:?}"
    );
    let mismatched = amendment_report
        .details
        .iter()
        .any(|d| d.contains("does not match") && d.contains("original_signer_key_id"));
    assert!(
        mismatched,
        "verifier must explicitly surface the original_signer_key_id mismatch: {amendment_report:?}"
    );
}

#[test]
fn non_amendment_bundle_omits_amends_field_from_wire_form() {
    let tmp = TempDir::new().expect("tmpdir");
    let path = tmp.path().join("no-amendment.witness");

    let signing_key = generate_signing_key();
    let verifying = signing_key.verifying_key();
    let pem = encode_public_key_pem(&verifying).expect("pem");
    let kid = key_id(&verifying);
    let signer = EphemeralSigner { key: signing_key };

    let inputs = make_inputs(pem, kid, "fresh capture, no chain", None);
    build_and_seal_bundle(&inputs, &signer, &path).expect("seal");

    let entries = read_bundle(&path).expect("read");
    let raw = entries.get(paths::MANIFEST).expect("manifest entry");
    let text = std::str::from_utf8(raw).expect("manifest is utf-8");
    assert!(
        !text.contains("\"amends\""),
        "non-amendment manifest must omit the amends key entirely so existing verifiers and \
         signature bytes stay identical: {text}"
    );
}
