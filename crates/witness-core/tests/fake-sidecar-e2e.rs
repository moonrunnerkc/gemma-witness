//! Hermetic end-to-end test using `witness-test-sidecar`.
//!
//! Drives the full pipeline (passes 0-3) against the fake server, seals a
//! `.witness` bundle with an ephemeral key, verifies it (signature, asset
//! hashes, fingerprint membership), then tampers one audio byte and asserts
//! verification fails at the asset-hash step.
//!
//! Unlike `day-4-e2e.rs`, this test does not require a real model and is
//! intended to run on every Linux and Windows CI job, closing the gap the
//! README calls out under "CI limitations" and "Cross-platform gaps".

use std::path::PathBuf;

use ed25519_dalek::Signer;
use witness_core::bundle_builder::{build_and_seal_bundle, paths, BundleInputs};
use witness_core::bundle_zip::{read_bundle, write_bundle, ZipEntry};
use witness_core::manifest::{CaptureEnvironment, ConsistencyLabel, ConsistencyVerdict};
use witness_core::signing::{encode_public_key_pem, generate_signing_key, key_id};
use witness_core::{
    verify_bundle, BundleSigner, EvidenceKind, EvidenceReference, WitnessCoreError,
};
use witness_inference::run_full_pipeline;

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

fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../..");
    p.canonicalize().unwrap_or(p)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_pipeline_round_trip_against_fake_sidecar() {
    let server = witness_test_sidecar::start_default()
        .await
        .expect("fake sidecar binds 127.0.0.1");

    let schema_path = workspace_root().join("spec/incident-schema.json");
    let schema_text = std::fs::read_to_string(&schema_path).expect("read schema");
    let schema: serde_json::Value = serde_json::from_str(&schema_text).expect("parse schema");

    let audio = workspace_root().join("tests/fixtures/day-3-scenarios/1/audio.wav");
    let images = vec![
        workspace_root().join("tests/fixtures/day-3-scenarios/1/image1.jpg"),
        workspace_root().join("tests/fixtures/day-3-scenarios/1/image2.jpg"),
    ];
    assert!(audio.exists(), "missing fixture audio: {audio:?}");
    for image in &images {
        assert!(image.exists(), "missing fixture image: {image:?}");
    }

    let pipeline = run_full_pipeline(&audio, &images, &schema, &server.endpoint)
        .await
        .expect("pipeline must complete against fake sidecar");

    assert!(
        pipeline.consistency.verdict == "consistent"
            || pipeline.consistency.verdict == "partially-consistent"
            || pipeline.consistency.verdict == "inconsistent",
        "verdict must be one of the allowed labels, got {}",
        pipeline.consistency.verdict
    );

    let signing_key = generate_signing_key();
    let verifying = signing_key.verifying_key();
    let pem = encode_public_key_pem(&verifying).expect("pem");
    let kid = key_id(&verifying);
    let signer = EphemeralSigner {
        key: signing_key.clone(),
    };

    // Fingerprint lookup mirrors what seal_bundle_cmd does: ask the active
    // sidecar what model is loaded, then resolve in the embedded registry.
    let active_model_id = witness_inference::fetch_active_model_id_default(&server.endpoint)
        .await
        .expect("models endpoint");
    let revision = match active_model_id.as_str() {
        "mlx-community/gemma-4-e4b-it-4bit" => "cc3b666c01c20395e0dcebd53854504c7d9821f9",
        _ => "main",
    };
    let fingerprint =
        witness_fingerprints::lookup(&active_model_id, revision).expect("registry lookup");

    let verdict_label = if pipeline.consistency.verdict == "consistent" {
        ConsistencyLabel::Consistent
    } else {
        ConsistencyLabel::Inconsistent
    };

    let mut report = pipeline.structure.report.clone();
    if report.evidence_references.is_empty() {
        report.evidence_references.push(EvidenceReference {
            kind: EvidenceKind::Audio,
            sha256: "0".repeat(64),
        });
    }

    let inputs = BundleInputs {
        audio_path: audio.clone(),
        image_paths: images.clone(),
        reasoning_trace_bytes: pipeline.consistency.reasoning_trace.as_bytes().to_vec(),
        incident_report: report,
        consistency: ConsistencyVerdict {
            verdict: verdict_label,
            summary: Some(pipeline.consistency.reason.clone()),
        },
        model_fingerprint: fingerprint.clone(),
        capture_environment: CaptureEnvironment {
            os: std::env::consts::OS.to_string(),
            hostname: None,
            app_version: "0.1.0-fake-sidecar-e2e".to_string(),
            captured_at: chrono::Utc::now().to_rfc3339(),
        },
        signer_public_key_pem: pem,
        signer_key_id: kid,
        inference_parameters: Some(witness_inference::inference_parameters_snapshot()),
        amends: None,
        pinned_audio_sha256: Some(pipeline.transcribe.audio_sha256_hex.clone()),
        pinned_image_sha256s: Some(
            pipeline
                .images
                .iter()
                .map(|i| i.image_sha256_hex.clone())
                .collect(),
        ),
    };

    let out_dir = workspace_root().join("target/test-artifacts");
    std::fs::create_dir_all(&out_dir).expect("mkdir artifacts");
    let bundle_path = out_dir.join(format!(
        "incident-fake-{}.witness",
        chrono::Utc::now().timestamp()
    ));
    build_and_seal_bundle(&inputs, &signer, &bundle_path).expect("seal");

    let known: Vec<witness_core::KnownFingerprint> = vec![fingerprint.clone().into()];
    let report = verify_bundle(&bundle_path, &known).expect("verify clean");
    assert!(
        report.is_ok(),
        "clean verification must pass: details={:?}",
        report.details
    );

    // Preserve the clean bundle so a reviewer can drag it into the static
    // verifier and see three green checks before opening the tampered sibling.
    let clean_path = bundle_path.with_extension("clean.witness");
    std::fs::copy(&bundle_path, &clean_path).expect("snapshot clean bundle");

    let mut entries = read_bundle(&bundle_path).expect("read bundle");
    let audio_bytes = entries.get_mut(paths::AUDIO).expect("audio entry");
    audio_bytes[100] ^= 0x42;
    let zipped: Vec<ZipEntry> = entries
        .into_iter()
        .map(|(path, data)| ZipEntry { path, data })
        .collect();
    write_bundle(&bundle_path, &zipped).expect("rewrite tampered");

    let tampered = verify_bundle(&bundle_path, &known).expect("verify tampered");
    assert!(
        tampered.signature_valid,
        "signature must still validate after a non-signed-bytes tamper"
    );
    assert!(
        !tampered.assets_untampered,
        "asset-hash check must fail after a byte-level tamper"
    );
    assert!(
        tampered
            .details
            .iter()
            .any(|d| d.contains(paths::AUDIO) && d.contains("hash mismatch")),
        "details must call out the specific asset and the failure mode: {:?}",
        tampered.details
    );

    // Surface both on-disk paths so a reviewer running
    // `cargo test ... -- --nocapture` can drag the clean bundle into the
    // static verifier (three green checks), then the tampered sibling (red
    // on assets_untampered), without grepping the workspace.
    eprintln!(
        "\nfake-sidecar-e2e: bundles ready for the static verifier:\n  clean    {}\n  tampered {}\n",
        clean_path.display(),
        bundle_path.display(),
    );

    server.shutdown().await;
}
