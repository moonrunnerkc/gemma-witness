//! Degraded-path coverage for the bundle reader and verifier.
//!
//! Each test constructs a known-bad bundle (corrupt ZIP structure,
//! oversized blob, malformed signature, replayed manifest, etc.) and
//! asserts the right gate rejects it with a recognizable error. These
//! complement the positive-path tests in `bundle_roundtrip.rs` and the
//! tamper tests in `transport_survival.rs` by walking through the
//! failure modes a security review will ask about.

use std::path::PathBuf;

use base64::Engine;
use ed25519_dalek::Signer;
use sha2::Digest;
use tempfile::TempDir;
use witness_core::bundle_builder::{build_and_seal_bundle, paths, BundleInputs};
use witness_core::bundle_zip::{read_bundle, write_bundle, ZipEntry};
use witness_core::canonical::canonicalize;
use witness_core::manifest::{
    CaptureEnvironment, ConsistencyLabel, ConsistencyVerdict, Manifest, ModelFingerprint,
    SignatureDocument, SignerAttestation,
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

fn make_inputs(pem: String, kid: String) -> BundleInputs {
    BundleInputs {
        audio_path: fixture_audio(),
        image_paths: vec![fixture_image()],
        reasoning_trace_bytes: b"<think>verbatim thinking trace</think>".to_vec(),
        incident_report: IncidentReport {
            timestamp: "2026-05-15T10:00:00Z".to_string(),
            location: Location {
                lat: Some(39.7),
                lng: Some(-105.0),
                description: "Degraded-path test capture site".to_string(),
            },
            witness_contact: None,
            incident_type: IncidentType::SafetyHazard,
            narrative_summary: "Degraded-path integration test scaffolding.".to_string(),
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
            captured_at: "2026-05-15T10:01:00Z".to_string(),
        },
        signer_public_key_pem: pem,
        signer_key_id: kid,
        inference_parameters: None,
        amends: None,
        pinned_audio_sha256: None,
        pinned_image_sha256s: None,
    }
}

fn sign_and_seal(
    out: &std::path::Path,
) -> (
    Vec<witness_core::KnownFingerprint>,
    ed25519_dalek::SigningKey,
) {
    let signing_key = generate_signing_key();
    let verifying = signing_key.verifying_key();
    let pem = encode_public_key_pem(&verifying).expect("pem");
    let kid = key_id(&verifying);
    let signer = EphemeralSigner {
        key: signing_key.clone(),
    };
    let inputs = make_inputs(pem, kid);
    build_and_seal_bundle(&inputs, &signer, out).expect("seal");
    (vec![inputs.model_fingerprint.clone().into()], signing_key)
}

// ----------------------------------------------------------------------------
// ZIP-layer corruption
// ----------------------------------------------------------------------------

#[test]
fn truncated_zip_is_rejected_by_reader() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("incident.witness");
    let (_known, _key) = sign_and_seal(&bundle);

    // Lop off the last 200 bytes, which contain the End of Central
    // Directory record. The ZIP crate must refuse the archive cleanly.
    let mut bytes = std::fs::read(&bundle).unwrap();
    let new_len = bytes.len().saturating_sub(200);
    bytes.truncate(new_len);
    std::fs::write(&bundle, &bytes).unwrap();

    let err = read_bundle(&bundle).expect_err("read must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("ZIP")
            || msg.contains("zip")
            || msg.contains("end of")
            || msg.contains("invalid"),
        "expected a ZIP-structure error, got {msg}"
    );
}

#[test]
fn zip_entry_with_path_traversal_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("incident.witness");

    // Hand-build a tiny ZIP whose only entry name is "../etc/passwd".
    // The reader's validate_entry_name must reject before any payload
    // reaches the manifest deserializer.
    let entries = vec![ZipEntry {
        path: "../etc/passwd".to_string(),
        data: b"contents".to_vec(),
    }];
    let write_err = write_bundle(&bundle, &entries).err();
    if let Some(err) = write_err {
        // Writer enforces the same rule the reader does. Either layer
        // refusing the name is acceptable; the invariant is that no
        // bundle on disk can carry such an entry.
        let msg = format!("{err}");
        assert!(
            msg.contains("path") || msg.contains("traversal") || msg.contains("entry"),
            "writer must reject path-traversal entry names, got {msg}"
        );
        return;
    }
    // If the writer didn't reject, the reader must.
    let read_err = read_bundle(&bundle).expect_err("reader must reject");
    let msg = format!("{read_err}");
    assert!(
        msg.contains("path")
            || msg.contains("traversal")
            || msg.contains("..")
            || msg.contains("entry"),
        "reader must surface a path-traversal error, got {msg}"
    );
}

// ----------------------------------------------------------------------------
// Manifest-layer malformation
// ----------------------------------------------------------------------------

#[test]
fn manifest_with_lone_surrogate_fails_to_parse() {
    // \uD800 is a high surrogate; without a paired low surrogate, the
    // sequence is invalid UTF-8 and not a legal JSON string. The verifier
    // never reaches signature checking; the bundle is malformed at the
    // structural layer.
    let payload = b"{\"manifest_version\":1,\"k\":\"\xed\xa0\x80\"}";
    let parsed: Result<Manifest, _> = serde_json::from_slice(payload);
    assert!(
        parsed.is_err(),
        "lone surrogate must be rejected at the parser"
    );
}

#[test]
fn attestation_payload_exceeding_cap_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("incident.witness");
    let (known, signing_key) = sign_and_seal(&bundle);

    let mut entries = read_bundle(&bundle).unwrap();
    let manifest_bytes = entries.get_mut("manifest.json").unwrap();
    let mut parsed: Manifest = serde_json::from_slice(manifest_bytes).unwrap();

    // Promote to v2 so the attestation field is legal, then attach a
    // 24 KiB base64 blob (above the 22,528-character cap).
    parsed.manifest_version = 2;
    parsed.signer.algorithm = "ed25519".to_string();
    parsed.signer.attestation = Some(SignerAttestation {
        format: "apple-sep-v1-fixture".to_string(),
        payload_b64: "A".repeat(24_000),
        certificate_chain_b64: None,
    });

    // Re-sign so the manifest is otherwise valid; the attestation cap is
    // the only thing under test.
    let canonical = canonicalize(&parsed).unwrap();
    let new_sig = signing_key.sign(&canonical);
    let sig_doc = SignatureDocument {
        algorithm: "ed25519".to_string(),
        key_id: parsed.signer.key_id.clone(),
        signature_b64: base64::engine::general_purpose::STANDARD.encode(new_sig.to_bytes()),
        signed_payload: paths::MANIFEST.to_string(),
        canonicalization: "rfc8785".to_string(),
    };
    *manifest_bytes = serde_json::to_vec(&parsed).unwrap();
    *entries.get_mut("signature.json").unwrap() = serde_json::to_vec(&sig_doc).unwrap();

    let zipped: Vec<ZipEntry> = entries
        .into_iter()
        .map(|(path, data)| ZipEntry { path, data })
        .collect();
    write_bundle(&bundle, &zipped).unwrap();

    let report = verify_bundle(&bundle, &known).expect("verify");
    assert!(
        !report.signature_valid,
        "oversized attestation must fail the signature row"
    );
    assert!(
        report
            .details
            .iter()
            .any(|d| d.contains("attestation") && d.contains("cap")),
        "details should name the attestation cap: {:?}",
        report.details
    );
}

// ----------------------------------------------------------------------------
// Signature-document malformation
// ----------------------------------------------------------------------------

#[test]
fn signature_with_invalid_base64_padding_fails() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("incident.witness");
    let (known, _key) = sign_and_seal(&bundle);

    let mut entries = read_bundle(&bundle).unwrap();
    let sig_bytes = entries.get_mut("signature.json").unwrap();
    let mut sig_doc: SignatureDocument = serde_json::from_slice(sig_bytes).unwrap();
    // Replace the signature bytes with something whose base64 padding is
    // structurally wrong (trailing single '=' on a length not divisible
    // by 4 minus 1). The verifier should surface the decode error rather
    // than panic or accept it.
    sig_doc.signature_b64 = "AAAA=".to_string();
    *sig_bytes = serde_json::to_vec(&sig_doc).unwrap();

    let zipped: Vec<ZipEntry> = entries
        .into_iter()
        .map(|(path, data)| ZipEntry { path, data })
        .collect();
    write_bundle(&bundle, &zipped).unwrap();

    let report = verify_bundle(&bundle, &known).expect("verify");
    assert!(
        !report.signature_valid,
        "malformed base64 must fail signature"
    );
    assert!(
        report.details.iter().any(|d| d.contains("base64")),
        "details should name the base64 decode failure: {:?}",
        report.details
    );
}

#[test]
fn signature_with_wrong_canonicalization_value_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("incident.witness");
    let (known, _key) = sign_and_seal(&bundle);

    let mut entries = read_bundle(&bundle).unwrap();
    let sig_bytes = entries.get_mut("signature.json").unwrap();
    let mut sig_doc: SignatureDocument = serde_json::from_slice(sig_bytes).unwrap();
    sig_doc.canonicalization = "json-c14n".to_string();
    *sig_bytes = serde_json::to_vec(&sig_doc).unwrap();

    let zipped: Vec<ZipEntry> = entries
        .into_iter()
        .map(|(path, data)| ZipEntry { path, data })
        .collect();
    write_bundle(&bundle, &zipped).unwrap();

    let report = verify_bundle(&bundle, &known).expect("verify");
    assert!(
        !report.signature_valid,
        "non-rfc8785 canonicalization must fail"
    );
    assert!(
        report
            .details
            .iter()
            .any(|d| d.contains("canonicalization") && d.contains("rfc8785")),
        "details should name the expected canonicalization: {:?}",
        report.details
    );
}

#[test]
fn signature_with_wrong_signed_payload_value_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("incident.witness");
    let (known, _key) = sign_and_seal(&bundle);

    let mut entries = read_bundle(&bundle).unwrap();
    let sig_bytes = entries.get_mut("signature.json").unwrap();
    let mut sig_doc: SignatureDocument = serde_json::from_slice(sig_bytes).unwrap();
    sig_doc.signed_payload = "audio.wav".to_string();
    *sig_bytes = serde_json::to_vec(&sig_doc).unwrap();

    let zipped: Vec<ZipEntry> = entries
        .into_iter()
        .map(|(path, data)| ZipEntry { path, data })
        .collect();
    write_bundle(&bundle, &zipped).unwrap();

    let report = verify_bundle(&bundle, &known).expect("verify");
    assert!(!report.signature_valid, "wrong signed_payload must fail");
    assert!(
        report.details.iter().any(|d| d.contains("signed_payload")),
        "details should name the signed_payload mismatch: {:?}",
        report.details
    );
}

// ----------------------------------------------------------------------------
// Replay / freshness
// ----------------------------------------------------------------------------

#[test]
fn replay_with_bumped_created_at_invalidates_the_signature() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("incident.witness");
    let (known, _key) = sign_and_seal(&bundle);

    let mut entries = read_bundle(&bundle).unwrap();
    let manifest_bytes = entries.get_mut("manifest.json").unwrap();
    let mut parsed: Manifest = serde_json::from_slice(manifest_bytes).unwrap();
    // Bump the timestamp to "now plus one year" without re-signing. The
    // signature covers the canonicalized manifest, so any byte change in
    // the timestamp invalidates it.
    parsed.created_at = "2027-05-15T10:00:00Z".to_string();
    *manifest_bytes = serde_json::to_vec(&parsed).unwrap();

    let zipped: Vec<ZipEntry> = entries
        .into_iter()
        .map(|(path, data)| ZipEntry { path, data })
        .collect();
    write_bundle(&bundle, &zipped).unwrap();

    let report = verify_bundle(&bundle, &known).expect("verify");
    assert!(
        !report.signature_valid,
        "replay with bumped timestamp must fail signature"
    );
}

// ----------------------------------------------------------------------------
// Asset-layer hash mismatch on a non-audio asset
// ----------------------------------------------------------------------------

#[test]
fn flipping_a_byte_in_a_packed_image_fails_assets() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("incident.witness");
    let (known, _key) = sign_and_seal(&bundle);

    let mut entries = read_bundle(&bundle).unwrap();
    let image_path = entries
        .keys()
        .find(|k| k.ends_with(".jpg"))
        .cloned()
        .expect("expect at least one image entry");
    let image_bytes = entries.get_mut(&image_path).unwrap();
    image_bytes[0] ^= 0x01;
    let _bumped_sha = sha2::Sha256::digest(&image_bytes[..]);
    let zipped: Vec<ZipEntry> = entries
        .into_iter()
        .map(|(path, data)| ZipEntry { path, data })
        .collect();
    write_bundle(&bundle, &zipped).unwrap();

    let report = verify_bundle(&bundle, &known).expect("verify");
    assert!(
        !report.assets_untampered,
        "image byte mutation must fail the assets row"
    );
    assert!(
        report
            .details
            .iter()
            .any(|d| d.contains(".jpg") && d.contains("hash")),
        "details should name the image and the hash mismatch: {:?}",
        report.details
    );
}
