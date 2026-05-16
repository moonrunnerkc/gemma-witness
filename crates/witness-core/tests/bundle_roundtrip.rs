//! Sign, verify, then tamper at the asset layer and assert verification
//! fails at the asset hash step (not at the signature step).

use std::path::PathBuf;

use base64::Engine;
use ed25519_dalek::Signer;
use sha2::Digest;
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

#[test]
fn fresh_bundle_round_trip_verifies() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("incident.witness");
    let (known, _key) = sign_and_seal(&bundle);
    let report = verify_bundle(&bundle, &known).expect("verify");
    assert!(report.is_ok(), "expected clean verify, got {report:?}");
}

/// Regression for audit finding T-1/V-3. Stages a per-capture working
/// directory, copies the fixture audio into it, "inference" hashes those
/// bytes, then a malicious process replaces the file before seal. Seal must
/// abort with [`WitnessCoreError::AssetTampered`] rather than silently
/// signing the swapped bytes.
#[test]
fn rejects_seal_when_audio_changes_between_inference_and_seal() {
    let tmp = TempDir::new().unwrap();
    let staged_audio = tmp.path().join("audio.wav");
    let staged_image = tmp.path().join("image.jpg");
    std::fs::copy(fixture_audio(), &staged_audio).expect("copy audio");
    std::fs::copy(fixture_image(), &staged_image).expect("copy image");

    // "Inference" reads the bytes off disk and records the hash.
    let audio_bytes = std::fs::read(&staged_audio).expect("read audio");
    let image_bytes = std::fs::read(&staged_image).expect("read image");
    let pinned_audio_sha256 = hex::encode(sha2::Sha256::digest(&audio_bytes));
    let pinned_image_sha256 = hex::encode(sha2::Sha256::digest(&image_bytes));

    // Attacker swaps the audio file between inference and seal.
    let mut tampered = audio_bytes.clone();
    if let Some(byte) = tampered.last_mut() {
        *byte ^= 0xFF;
    }
    std::fs::write(&staged_audio, &tampered).expect("tamper write");

    let signing_key = generate_signing_key();
    let verifying = signing_key.verifying_key();
    let pem = encode_public_key_pem(&verifying).expect("pem");
    let kid = key_id(&verifying);
    let signer = EphemeralSigner { key: signing_key };

    let mut inputs = make_inputs(pem, kid);
    inputs.audio_path = staged_audio.clone();
    inputs.image_paths = vec![staged_image];
    inputs.pinned_audio_sha256 = Some(pinned_audio_sha256.clone());
    inputs.pinned_image_sha256s = Some(vec![pinned_image_sha256]);

    let out = tmp.path().join("incident.witness");
    let err = build_and_seal_bundle(&inputs, &signer, &out)
        .expect_err("seal must refuse a tampered audio asset");
    match err {
        WitnessCoreError::AssetTampered {
            path,
            pinned_sha256,
            seal_sha256,
        } => {
            assert_eq!(path, staged_audio);
            assert_eq!(pinned_sha256, pinned_audio_sha256);
            assert_ne!(seal_sha256, pinned_audio_sha256);
        }
        other => panic!("expected AssetTampered, got {other:?}"),
    }
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
    let _ = other_pem;
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

/// Audit finding V-4: the fingerprint check matches on the
/// `(model_id, revision, sha256)` triple, not on SHA-256 alone. A bundle
/// that claims a different model_id than the registry owns for a known
/// SHA-256 must fail the row.
#[test]
fn rejects_bundle_when_manifest_claims_different_model_id_for_known_sha() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("incident.witness");
    let (mut known, _key) = sign_and_seal(&bundle);
    // Keep the SHA-256 the bundle was sealed against, but tell the verifier
    // the registry owns it under a different model_id/revision than what
    // the bundle claims.
    if let Some(entry) = known.get_mut(0) {
        entry.model_id = "rogue/model".to_string();
        entry.revision = "rogue-revision".to_string();
    }
    let report = verify_bundle(&bundle, &known).expect("verify");
    assert!(
        !report.model_fingerprint_known,
        "fingerprint check must fail when the registry claims a different (model_id, revision) for the same SHA-256"
    );
    assert!(
        report
            .details
            .iter()
            .any(|d| d.contains("registered but for")),
        "details should surface the triple mismatch: {:?}",
        report.details
    );
}

#[test]
fn rejects_bundle_after_model_fingerprint_change() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("incident.witness");
    let (_known_original, _key) = sign_and_seal(&bundle);
    let new_known = vec![witness_core::KnownFingerprint {
        model_id: "unrelated/model".to_string(),
        revision: "vUnrelated".to_string(),
        sha256: "a".repeat(64),
    }];
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

#[test]
fn bundle_does_not_contain_standalone_public_key_pem() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("incident.witness");
    sign_and_seal(&bundle);
    let entries = read_bundle(&bundle).unwrap();
    assert!(
        !entries.contains_key("public_key.pem"),
        "bundle must not ship a standalone public_key.pem; signer.public_key_pem in the manifest \
         is the only authoritative copy",
    );
}

#[test]
fn rejects_bundle_with_unexpected_zip_entry() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("incident.witness");
    let (known, _key) = sign_and_seal(&bundle);

    let mut entries = read_bundle(&bundle).unwrap();
    entries.insert(
        "assets/images/img-99.jpg".to_string(),
        b"injected image not in manifest".to_vec(),
    );
    let zipped: Vec<ZipEntry> = entries
        .into_iter()
        .map(|(path, data)| ZipEntry { path, data })
        .collect();
    write_bundle(&bundle, &zipped).unwrap();

    let report = verify_bundle(&bundle, &known).expect("verify");
    assert!(
        !report.assets_untampered,
        "ZIP entry not bound by the signature must fail the asset-untampered check"
    );
    assert!(
        report.details.iter().any(|d| d.contains("img-99")),
        "details should call out the rogue entry by name: {:?}",
        report.details
    );
}

#[test]
fn rejects_bundle_with_signed_payload_tampered() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("incident.witness");
    let (known, _key) = sign_and_seal(&bundle);

    let mut entries = read_bundle(&bundle).unwrap();
    let sig_bytes = entries.get_mut("signature.json").unwrap();
    let mut parsed: SignatureDocument = serde_json::from_slice(sig_bytes).unwrap();
    parsed.signed_payload = "manifest-alternate.json".to_string();
    *sig_bytes = serde_json::to_vec(&parsed).unwrap();
    let zipped: Vec<ZipEntry> = entries
        .into_iter()
        .map(|(path, data)| ZipEntry { path, data })
        .collect();
    write_bundle(&bundle, &zipped).unwrap();

    let report = verify_bundle(&bundle, &known).expect("verify");
    assert!(
        !report.signature_valid,
        "signature.signed_payload must be exactly 'manifest.json'"
    );
}

#[test]
fn rejects_bundle_with_algorithm_lie() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("incident.witness");
    let (known, _key) = sign_and_seal(&bundle);

    let mut entries = read_bundle(&bundle).unwrap();
    let sig_bytes = entries.get_mut("signature.json").unwrap();
    let mut parsed: SignatureDocument = serde_json::from_slice(sig_bytes).unwrap();
    parsed.algorithm = "future-pq-sig".to_string();
    *sig_bytes = serde_json::to_vec(&parsed).unwrap();
    let zipped: Vec<ZipEntry> = entries
        .into_iter()
        .map(|(path, data)| ZipEntry { path, data })
        .collect();
    write_bundle(&bundle, &zipped).unwrap();

    let report = verify_bundle(&bundle, &known).expect("verify");
    assert!(
        !report.signature_valid,
        "signature.algorithm claim must match the verifier's supported set"
    );
}

/// Construct a valid signature for the manifest then mutate the `s` scalar
/// by adding the curve order `L` modulo 2^256. The malleated signature is
/// valid under the legacy non-strict verifier (`Verifier::verify`) but
/// rejected by `verify_strict`.
#[test]
fn rejects_malleated_signature() {
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("incident.witness");
    let (known, signing_key) = sign_and_seal(&bundle);

    let mut entries = read_bundle(&bundle).unwrap();
    let sig_bytes = entries.get_mut("signature.json").unwrap();
    let mut sig_doc: SignatureDocument = serde_json::from_slice(sig_bytes).unwrap();

    // Recover the raw signature, malleate s -> s + L (mod 2^256).
    let raw = base64::engine::general_purpose::STANDARD
        .decode(sig_doc.signature_b64.as_bytes())
        .unwrap();
    assert_eq!(raw.len(), 64);
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&raw[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&raw[32..]);

    // L (the Ed25519 group order) in little-endian, per RFC 8032 §5.1.
    let order_le: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut carry: u16 = 0;
    let mut new_s = [0u8; 32];
    for i in 0..32 {
        let sum = s_bytes[i] as u16 + order_le[i] as u16 + carry;
        new_s[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }

    // Only meaningful if the addition did not wrap past 256 bits.
    if carry == 0 {
        let mut malleated = [0u8; 64];
        malleated[..32].copy_from_slice(&r_bytes);
        malleated[32..].copy_from_slice(&new_s);
        sig_doc.signature_b64 = base64::engine::general_purpose::STANDARD.encode(malleated);
        *sig_bytes = serde_json::to_vec(&sig_doc).unwrap();
        let zipped: Vec<ZipEntry> = entries
            .into_iter()
            .map(|(path, data)| ZipEntry { path, data })
            .collect();
        write_bundle(&bundle, &zipped).unwrap();

        let report = verify_bundle(&bundle, &known).expect("verify");
        assert!(
            !report.signature_valid,
            "strict Ed25519 must reject a non-canonical s scalar; if this passes, \
             verifier is not using verify_strict",
        );
    }
    // Keep `signing_key` alive so the original sign_and_seal context is meaningful.
    let _ = signing_key;
}
