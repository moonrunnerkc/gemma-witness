//! Day 4 end-to-end test.
//!
//! Drives the full chain: live sidecar inference (passes 0-3), bundle build
//! and seal with an ephemeral Ed25519 key, round-trip verification, then a
//! single-byte audio tamper that must fail at the asset-hash step.
//!
//! If the sidecar is not reachable on `DEFAULT_ENDPOINT`, the test prints a
//! clear skip notice and returns success. Run the sidecar
//! (`inference/mlx-sidecar/start.sh`) for a real assertion.

use std::path::PathBuf;
use std::time::Duration;

use ed25519_dalek::Signer;
use witness_core::bundle_builder::{build_and_seal_bundle, paths, BundleInputs};
use witness_core::bundle_zip::{read_bundle, write_bundle, ZipEntry};
use witness_core::manifest::{
    CaptureEnvironment, ConsistencyLabel, ConsistencyVerdict, ModelFingerprint,
};
use witness_core::signing::{encode_public_key_pem, generate_signing_key, key_id};
use witness_core::{
    verify_bundle, BundleSigner, EvidenceKind, EvidenceReference, WitnessCoreError,
};
use witness_inference::{run_full_pipeline, DEFAULT_ENDPOINT};

struct EphemeralSigner {
    key: ed25519_dalek::SigningKey,
}

impl BundleSigner for EphemeralSigner {
    fn sign(&self, payload: &[u8]) -> Result<[u8; 64], WitnessCoreError> {
        Ok(self.key.sign(payload).to_bytes())
    }
}

fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../..");
    p.canonicalize().unwrap_or(p)
}

fn fixture_audio() -> PathBuf {
    workspace_root().join("tests/fixtures/day-3-scenarios/1/audio.wav")
}

fn fixture_images() -> Vec<PathBuf> {
    let base = workspace_root().join("tests/fixtures/day-3-scenarios/1");
    vec![base.join("image1.jpg"), base.join("image2.jpg")]
}

fn artifacts_dir() -> PathBuf {
    workspace_root().join("target/test-artifacts")
}

fn known_fingerprint_from_spec() -> ModelFingerprint {
    // Reads from the unified fingerprint registry rather than the per-sidecar
    // JSON. The registry now lives at inference/fingerprints/, and the seeded
    // mlx-community entry has been pinned to the same revision since Day 4.
    let raw = std::fs::read_to_string(
        workspace_root()
            .join("inference/fingerprints/mlx-community__gemma-4-e4b-it-4bit__cc3b666c.json"),
    )
    .expect("registry entry for the mlx-community model must exist");
    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
    ModelFingerprint {
        model_id: parsed["model_id"].as_str().unwrap().to_string(),
        revision: parsed["revision"].as_str().unwrap().to_string(),
        sha256: parsed["files"][0]["sha256"].as_str().unwrap().to_string(),
    }
}

async fn sidecar_alive() -> bool {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    let url = format!("{}/v1/models", DEFAULT_ENDPOINT);
    client
        .get(&url)
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn day_4_e2e_capture_seal_verify_tamper() {
    if !sidecar_alive().await {
        eprintln!(
            "SKIP day-4-e2e: sidecar at {} unreachable. start inference/mlx-sidecar/start.sh and re-run.",
            DEFAULT_ENDPOINT
        );
        return;
    }

    let schema_path = workspace_root().join("spec/incident-schema.json");
    let schema_text = std::fs::read_to_string(&schema_path).expect("read schema");
    let schema: serde_json::Value = serde_json::from_str(&schema_text).expect("parse schema");

    let audio = fixture_audio();
    let images = fixture_images();
    assert!(audio.exists(), "missing fixture audio: {audio:?}");
    for image in &images {
        assert!(image.exists(), "missing fixture image: {image:?}");
    }

    println!("--- pipeline begin: audio={audio:?}, images={images:?}");
    let pipeline = run_full_pipeline(&audio, &images, &schema, DEFAULT_ENDPOINT)
        .await
        .expect("pipeline must complete against live sidecar");
    println!(
        "--- pipeline ok: total_ms={}, retries_pass1={}, verdict={}",
        pipeline.total_latency_ms, pipeline.structure.retries_used, pipeline.consistency.verdict
    );

    let signing_key = generate_signing_key();
    let verifying = signing_key.verifying_key();
    let pem = encode_public_key_pem(&verifying).expect("pem");
    let kid = key_id(&verifying);
    let signer = EphemeralSigner {
        key: signing_key.clone(),
    };
    let fingerprint = known_fingerprint_from_spec();

    let verdict_label = if pipeline.consistency.verdict == "consistent" {
        ConsistencyLabel::Consistent
    } else {
        ConsistencyLabel::Inconsistent
    };

    let inputs = BundleInputs {
        audio_path: audio.clone(),
        image_paths: images.clone(),
        reasoning_trace_bytes: pipeline.consistency.reasoning_trace.as_bytes().to_vec(),
        incident_report: {
            let mut rpt = pipeline.structure.report.clone();
            if rpt.evidence_references.is_empty() {
                rpt.evidence_references.push(EvidenceReference {
                    kind: EvidenceKind::Audio,
                    sha256: "0".repeat(64),
                });
            }
            rpt
        },
        consistency: ConsistencyVerdict {
            verdict: verdict_label,
            summary: Some(pipeline.consistency.reason.clone()),
        },
        model_fingerprint: fingerprint.clone(),
        capture_environment: CaptureEnvironment {
            os: std::env::consts::OS.to_string(),
            hostname: hostname_opt(),
            app_version: "0.1.0-day4-e2e".to_string(),
            captured_at: chrono::Utc::now().to_rfc3339(),
        },
        signer_public_key_pem: pem,
        signer_key_id: kid,
        inference_parameters: Some(witness_inference::inference_parameters_snapshot()),
    };

    let out_dir = artifacts_dir();
    std::fs::create_dir_all(&out_dir).expect("mkdir artifacts");
    let bundle_path = out_dir.join(format!(
        "incident-day4-{}.witness",
        chrono::Utc::now().timestamp()
    ));
    let bundle_id = build_and_seal_bundle(&inputs, &signer, &bundle_path).expect("seal");
    println!("--- bundle sealed: id={bundle_id} path={bundle_path:?}");

    let known = vec![fingerprint.sha256.clone()];
    let report = verify_bundle(&bundle_path, &known).expect("verify");
    assert!(report.is_ok(), "verification failed: {report:?}");
    println!("--- verify clean: {report:?}");

    let mut entries = read_bundle(&bundle_path).expect("read");
    let audio_bytes = entries.get_mut(paths::AUDIO).expect("audio entry");
    audio_bytes[100] ^= 0x42;
    let zipped: Vec<ZipEntry> = entries
        .into_iter()
        .map(|(path, data)| ZipEntry { path, data })
        .collect();
    write_bundle(&bundle_path, &zipped).expect("rewrite");

    let tampered = verify_bundle(&bundle_path, &known).expect("verify tampered");
    assert!(tampered.signature_valid, "signature still ok");
    assert!(!tampered.assets_untampered, "asset hash must fail");
    assert!(tampered
        .details
        .iter()
        .any(|d| d.contains(paths::AUDIO) && d.contains("hash mismatch")));
    println!("--- tamper detected: details={:?}", tampered.details);
}

fn hostname_opt() -> Option<String> {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
}
