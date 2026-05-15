//! "Survives email" invariant: a `.witness` bundle stays verifiable after
//! the ZIP container is rewritten with different settings.
//!
//! The bundle's signature covers the JCS-canonicalized manifest bytes, not
//! the ZIP container, and the asset checks recompute SHA-256 over raw asset
//! bytes pulled back out of the archive. Any well-behaved ZIP tool that
//! preserves entry contents and names therefore preserves the verification
//! outcome, regardless of compression method, entry ordering, or extra-field
//! noise it adds.
//!
//! This test confirms that property by sealing a bundle the normal way,
//! re-zipping the same entries with a different compression method, and
//! verifying the result.

use std::io::{Read, Seek, Write};
use std::path::PathBuf;

use ed25519_dalek::Signer;
use tempfile::TempDir;
use witness_core::bundle_builder::{build_and_seal_bundle, BundleInputs};
use witness_core::bundle_zip::read_bundle;
use witness_core::manifest::{
    CaptureEnvironment, ConsistencyLabel, ConsistencyVerdict, ModelFingerprint,
};
use witness_core::signing::{encode_public_key_pem, generate_signing_key, key_id};
use witness_core::{
    verify_bundle, BundleSigner, EvidenceKind, EvidenceReference, IncidentReport, IncidentType,
    Location, WitnessCoreError,
};
use zip::write::SimpleFileOptions;
use zip::CompressionMethod;

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

fn seal_clean_bundle(out: &std::path::Path) -> Vec<witness_core::KnownFingerprint> {
    let signing_key = generate_signing_key();
    let verifying = signing_key.verifying_key();
    let pem = encode_public_key_pem(&verifying).expect("pem");
    let kid = key_id(&verifying);
    let signer = EphemeralSigner { key: signing_key };

    let inputs = BundleInputs {
        audio_path: fixture_audio(),
        image_paths: vec![fixture_image()],
        reasoning_trace_bytes: b"transport-survival trace".to_vec(),
        incident_report: IncidentReport {
            timestamp: "2026-05-13T10:00:00Z".to_string(),
            location: Location {
                lat: None,
                lng: None,
                description: "transport-survival test".to_string(),
            },
            witness_contact: None,
            incident_type: IncidentType::SafetyHazard,
            narrative_summary: "transport survival test bundle".to_string(),
            severity: 1,
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
            model_id: "transport/test".to_string(),
            revision: "main".to_string(),
            sha256: "f".repeat(64),
        },
        capture_environment: CaptureEnvironment {
            os: "macOS".to_string(),
            hostname: None,
            app_version: "0.1.0-transport-survival".to_string(),
            captured_at: "2026-05-13T10:01:00Z".to_string(),
        },
        signer_public_key_pem: pem,
        signer_key_id: kid,
        inference_parameters: None,
        amends: None,
        pinned_audio_sha256: None,
        pinned_image_sha256s: None,
    };
    build_and_seal_bundle(&inputs, &signer, out).expect("seal");
    vec![inputs.model_fingerprint.into()]
}

/// Rewrite `src` to `dst` using the supplied compression method. The entry
/// names, contents, and ordering are preserved; only the container metadata
/// changes. Simulates the kind of mutation a mail relay or chat platform may
/// apply when a recipient downloads and re-uploads the file.
fn rezip_with_method<W: Write + Seek>(
    entries: &std::collections::BTreeMap<String, Vec<u8>>,
    writer: W,
    method: CompressionMethod,
) {
    let mut zip = zip::ZipWriter::new(writer);
    let options = SimpleFileOptions::default()
        .compression_method(method)
        .unix_permissions(0o644);
    for (name, data) in entries {
        zip.start_file(name, options).expect("start_file");
        zip.write_all(data).expect("write entry");
    }
    zip.finish().expect("finish");
}

#[test]
fn deflated_rezip_preserves_verification() {
    let tmp = TempDir::new().expect("tmpdir");
    let original = tmp.path().join("original.witness");
    let rezipped = tmp.path().join("rezipped.witness");

    let known = seal_clean_bundle(&original);
    let entries = read_bundle(&original).expect("read original");

    let file = std::fs::File::create(&rezipped).expect("create rezip target");
    rezip_with_method(&entries, file, CompressionMethod::Deflated);

    let report = verify_bundle(&rezipped, &known).expect("verify rezipped");
    assert!(
        report.is_ok(),
        "deflate-rezipped bundle must still pass every check: {report:?}"
    );
}

#[test]
fn reordered_entries_preserve_verification() {
    let tmp = TempDir::new().expect("tmpdir");
    let original = tmp.path().join("original.witness");
    let rezipped = tmp.path().join("reordered.witness");

    let known = seal_clean_bundle(&original);
    let entries = read_bundle(&original).expect("read original");

    // Write entries in reverse-sorted order. BTreeMap is sorted naturally;
    // we deliberately walk it in reverse to push the manifest near the end.
    let file = std::fs::File::create(&rezipped).expect("create rezip target");
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .unix_permissions(0o644);
    for (name, data) in entries.iter().rev() {
        zip.start_file(name, options).expect("start_file");
        zip.write_all(data).expect("write entry");
    }
    zip.finish().expect("finish");

    let report = verify_bundle(&rezipped, &known).expect("verify reordered");
    assert!(
        report.is_ok(),
        "reordered ZIP entries must still verify because checks are content-keyed: {report:?}"
    );
}

#[test]
fn flipping_a_byte_in_rezipped_audio_still_fails_assets() {
    let tmp = TempDir::new().expect("tmpdir");
    let original = tmp.path().join("original.witness");
    let rezipped = tmp.path().join("tampered.witness");

    let known = seal_clean_bundle(&original);
    let mut entries = read_bundle(&original).expect("read original");
    let audio = entries
        .get_mut("assets/audio.wav")
        .expect("audio entry present");
    audio[200] ^= 0x80;

    let file = std::fs::File::create(&rezipped).expect("create rezip target");
    rezip_with_method(&entries, file, CompressionMethod::Deflated);

    let report = verify_bundle(&rezipped, &known).expect("verify tampered rezip");
    assert!(
        report.signature_valid,
        "manifest signature stays valid because only an asset changed"
    );
    assert!(
        !report.assets_untampered,
        "asset hash check must fail under a byte-level audio mutation, even after deflate rezip"
    );
}

#[test]
fn rezip_roundtrip_decodes_entries_byte_for_byte() {
    let tmp = TempDir::new().expect("tmpdir");
    let original = tmp.path().join("original.witness");
    let rezipped = tmp.path().join("rezipped.witness");

    seal_clean_bundle(&original);
    let original_entries = read_bundle(&original).expect("read original");

    let file = std::fs::File::create(&rezipped).expect("create rezip target");
    rezip_with_method(&original_entries, file, CompressionMethod::Deflated);

    // Re-open the rezipped bundle through a third-party-style reader and
    // confirm every entry's bytes round-trip exactly. zip::ZipArchive
    // handles deflate transparently, which is the whole point of the
    // invariant.
    let f = std::fs::File::open(&rezipped).expect("open rezip");
    let mut archive = zip::ZipArchive::new(f).expect("parse rezip");
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).expect("entry by index");
        let name = entry.name().to_string();
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).expect("read entry");
        let original_bytes = original_entries
            .get(&name)
            .unwrap_or_else(|| panic!("rezip introduced unknown entry: {name}"));
        assert_eq!(
            &buf, original_bytes,
            "entry {name} must round-trip byte-for-byte through deflate rezip"
        );
    }
}
