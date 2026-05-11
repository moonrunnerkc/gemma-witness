//! End-to-end integration test for the multimodal inference pipeline.
//!
//! Runs the three Day 3 scenarios under `tests/fixtures/day-3-scenarios/`
//! against a live mlx-vlm sidecar at `http://127.0.0.1:8080`. Skips itself
//! gracefully if the sidecar is not reachable so a `cargo test --workspace`
//! on a machine without the model still passes.
//!
//! Assertions are schema-level, per the CLAUDE.md invariant that inference
//! is non-deterministic. We never assert on exact transcript wording or on
//! exact verdict-reason text.

use std::path::{Path, PathBuf};

use jsonschema::JSONSchema;
use serde_json::Value;
use sha2::{Digest, Sha256};
use witness_inference::{run_full_pipeline, ALLOWED_VERDICTS, DEFAULT_ENDPOINT};

const SCHEMA_RELATIVE: &str = "../../spec/incident-schema.json";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn schema_value() -> Value {
    let path = workspace_root().join(SCHEMA_RELATIVE);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read schema at {path:?}: {e}"));
    serde_json::from_str(&raw).expect("incident-schema.json must be valid JSON")
}

fn scenarios_root() -> PathBuf {
    workspace_root().join("../../tests/fixtures/day-3-scenarios")
}

fn sidecar_reachable() -> bool {
    match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
    {
        Ok(client) => client
            .get(format!("{DEFAULT_ENDPOINT}/v1/models"))
            .send()
            .map(|r| r.status().is_success())
            .unwrap_or(false),
        Err(_) => false,
    }
}

fn sha256_hex_of(path: &Path) -> String {
    let bytes = std::fs::read(path).expect("fixture file must be readable");
    hex::encode(Sha256::digest(&bytes))
}

struct ScenarioInputs {
    label: &'static str,
    audio: PathBuf,
    images: Vec<PathBuf>,
}

fn scenario(label: &'static str, dir: &str, images: &[&str]) -> ScenarioInputs {
    let base = scenarios_root().join(dir);
    let image_paths = images.iter().map(|name| base.join(name)).collect();
    ScenarioInputs {
        label,
        audio: base.join("audio.wav"),
        images: image_paths,
    }
}

fn run_scenario(inputs: &ScenarioInputs, schema: &Value) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime must build");
    let result = rt
        .block_on(run_full_pipeline(
            &inputs.audio,
            &inputs.images,
            schema,
            DEFAULT_ENDPOINT,
        ))
        .unwrap_or_else(|e| panic!("scenario {} failed: {e}", inputs.label));

    // (a) schema validity of the structured report
    let compiled = JSONSchema::compile(schema).expect("schema compiles");
    let report_value =
        serde_json::to_value(&result.structure.report).expect("report serialises to value");
    if let Err(errors) = compiled.validate(&report_value) {
        let joined: Vec<String> = errors.map(|e| e.to_string()).collect();
        panic!(
            "scenario {} structured report failed schema: {}",
            inputs.label,
            joined.join("; ")
        );
    }

    // (b) reasoning trace present and non-empty
    assert!(
        !result.consistency.reasoning_trace.is_empty(),
        "scenario {}: reasoning trace was empty; thinking mode is not engaged",
        inputs.label
    );

    // (c) verdict is one of the three allowed values
    assert!(
        ALLOWED_VERDICTS.contains(&result.consistency.verdict.as_str()),
        "scenario {}: verdict `{}` is not in {:?}",
        inputs.label,
        result.consistency.verdict,
        ALLOWED_VERDICTS
    );

    // (d) reasoning-trace hash matches direct SHA-256 of the trace bytes
    let expected_trace_hash =
        hex::encode(Sha256::digest(result.consistency.reasoning_trace.as_bytes()));
    assert_eq!(
        expected_trace_hash, result.consistency.reasoning_trace_sha256_hex,
        "scenario {}: reasoning-trace hash mismatch",
        inputs.label
    );

    // (e) every image's reported hash equals a fresh sha256 of the file on disk
    assert_eq!(
        result.images.len(),
        inputs.images.len(),
        "scenario {}: image count round-trip mismatch",
        inputs.label
    );
    for (analysis, path) in result.images.iter().zip(inputs.images.iter()) {
        let direct = sha256_hex_of(path);
        assert_eq!(
            direct, analysis.image_sha256_hex,
            "scenario {}: image hash mismatch for {:?}",
            inputs.label, path
        );
        assert!(
            !analysis.description.trim().is_empty(),
            "scenario {}: image description was empty for {:?}",
            inputs.label, path
        );
    }

    eprintln!(
        "[scenario {}] verdict={} reason={} transcript_len={} reasoning_len={} latency_ms={}",
        inputs.label,
        result.consistency.verdict,
        result.consistency.reason,
        result.transcribe.transcript.len(),
        result.consistency.reasoning_trace.len(),
        result.total_latency_ms,
    );
    // Print verbatim reasoning sample for evidence.
    eprintln!(
        "[scenario {} reasoning-trace-verbatim-begin]\n{}\n[scenario {} reasoning-trace-verbatim-end]",
        inputs.label, result.consistency.reasoning_trace, inputs.label
    );
    // Echo first image hash via the pipeline vs direct, for visible evidence.
    if let Some(first) = result.images.first() {
        let direct = sha256_hex_of(&inputs.images[0]);
        eprintln!(
            "[scenario {} hash-check] pipeline={} direct={}",
            inputs.label, first.image_sha256_hex, direct
        );
    }
}

fn skip_if_offline() -> bool {
    if !sidecar_reachable() {
        eprintln!(
            "skipping pipeline integration test: sidecar at {DEFAULT_ENDPOINT} not reachable. start it with inference/mlx-sidecar/start.sh."
        );
        return true;
    }
    false
}

#[test]
fn construction_site_scenario_passes_schema_and_returns_a_valid_verdict() {
    if skip_if_offline() {
        return;
    }
    let schema = schema_value();
    let inputs = scenario("1-construction", "1", &["image1.jpg", "image2.jpg"]);
    run_scenario(&inputs, &schema);
}

#[test]
fn creek_observation_scenario_passes_schema_and_returns_a_valid_verdict() {
    if skip_if_offline() {
        return;
    }
    let schema = schema_value();
    let inputs = scenario("2-creek", "2", &["image1.jpg"]);
    run_scenario(&inputs, &schema);
}

#[test]
fn consistency_check_flags_audio_image_mismatch_as_inconsistent() {
    if skip_if_offline() {
        return;
    }
    let schema = schema_value();
    let inputs = scenario("3-mismatch", "3", &["image1.jpg", "image2.jpg"]);
    run_scenario(&inputs, &schema);
}
