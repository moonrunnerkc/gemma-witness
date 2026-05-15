//! Validates assembled manifests against `spec/manifest-schema.json`.
//!
//! Catches drift between the Rust types in [`witness_core::manifest`] and
//! the JSON Schema the verifier and the spec both depend on. Each test
//! constructs a minimal valid manifest, serializes it, and asserts the
//! schema accepts it.

use std::path::PathBuf;

use jsonschema::JSONSchema;
use serde_json::Value;
use witness_core::bundle_builder::paths as bundle_paths;
use witness_core::manifest::{
    Assertions, AssetEntry, CaptureEnvironment, ConsistencyLabel, ConsistencyVerdict, Manifest,
    ModelFingerprint, ReasoningTrace, SignerInfo, MANIFEST_VERSION,
};
use witness_core::{
    EvidenceKind, EvidenceReference, IncidentReport, IncidentType, InferenceParameters, Location,
    PassParameters,
};

/// Load the manifest schema with the external `incident-schema.json` `$ref`
/// inlined. `jsonschema`'s default resolver only handles in-document refs;
/// the test loads both files off disk and splices the incident schema into
/// the position the `$ref` would resolve to, so validation can run fully
/// offline.
fn load_schema() -> Value {
    let mut manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_path.push("../../spec/manifest-schema.json");
    let manifest_raw = std::fs::read_to_string(&manifest_path).expect("read manifest-schema.json");
    let mut manifest_schema: Value =
        serde_json::from_str(&manifest_raw).expect("parse manifest-schema.json");

    let mut incident_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    incident_path.push("../../spec/incident-schema.json");
    let incident_raw = std::fs::read_to_string(&incident_path).expect("read incident-schema.json");
    let incident_schema: Value =
        serde_json::from_str(&incident_raw).expect("parse incident-schema.json");

    let slot = manifest_schema
        .pointer_mut("/properties/assertions/properties/gemma.witness.incident_report")
        .expect("incident_report slot exists in the manifest schema");
    *slot = incident_schema;

    manifest_schema
}

fn minimal_manifest() -> Manifest {
    Manifest {
        manifest_version: MANIFEST_VERSION,
        bundle_id: "11111111-2222-3333-4444-555555555555".to_string(),
        created_at: "2026-05-15T00:00:00Z".to_string(),
        signer: SignerInfo {
            algorithm: "ed25519".to_string(),
            public_key_pem: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"
                .to_string(),
            key_id: "0".repeat(64),
        },
        assets: vec![AssetEntry {
            path: bundle_paths::AUDIO.to_string(),
            media_type: "audio/wav".to_string(),
            sha256: "a".repeat(64),
            bytes: 1,
        }],
        assertions: Assertions {
            model_fingerprint: ModelFingerprint {
                model_id: "test/model".to_string(),
                revision: "main".to_string(),
                sha256: "b".repeat(64),
            },
            incident_report: IncidentReport {
                timestamp: "2026-05-15T00:00:00Z".to_string(),
                location: Location {
                    lat: None,
                    lng: None,
                    description: "unknown".to_string(),
                },
                witness_contact: None,
                incident_type: IncidentType::SafetyHazard,
                narrative_summary: "minimal manifest for schema validation".to_string(),
                severity: 1,
                notes: None,
                evidence_references: vec![EvidenceReference {
                    kind: EvidenceKind::Audio,
                    sha256: "c".repeat(64),
                }],
            },
            reasoning_trace: ReasoningTrace {
                asset_path: bundle_paths::REASONING.to_string(),
                sha256: "d".repeat(64),
                bytes: 1,
            },
            consistency_verdict: ConsistencyVerdict {
                verdict: ConsistencyLabel::Consistent,
                summary: None,
            },
            capture_environment: CaptureEnvironment {
                os: "macos".to_string(),
                hostname: None,
                app_version: "0.1.0".to_string(),
                captured_at: "2026-05-15T00:00:00Z".to_string(),
            },
            inference_parameters: None,
        },
    }
}

#[test]
fn manifest_without_inference_parameters_validates() {
    let schema = load_schema();
    let compiled = JSONSchema::compile(&schema).expect("compile schema");
    let payload = serde_json::to_value(minimal_manifest()).expect("serialize manifest");
    let result = compiled.validate(&payload);
    if let Err(errors) = result {
        let messages: Vec<String> = errors.map(|e| e.to_string()).collect();
        panic!("manifest without inference_parameters must validate: {messages:?}");
    }
}

#[test]
fn manifest_with_inference_parameters_validates() {
    let schema = load_schema();
    let compiled = JSONSchema::compile(&schema).expect("compile schema");
    let mut manifest = minimal_manifest();
    let mut passes = std::collections::BTreeMap::new();
    passes.insert(
        "transcribe".to_string(),
        PassParameters {
            temperature: 0.0,
            top_p: None,
            max_tokens: 500,
            visual_token_budget: None,
            prompt_sha256: "e".repeat(64),
        },
    );
    passes.insert(
        "analyze_image".to_string(),
        PassParameters {
            temperature: 0.2,
            top_p: None,
            max_tokens: 220,
            visual_token_budget: Some(280),
            prompt_sha256: "f".repeat(64),
        },
    );
    manifest.assertions.inference_parameters = Some(InferenceParameters {
        passes,
        sampling_seed: None,
        note: "advisory, schema-validation fixture".to_string(),
    });
    let payload = serde_json::to_value(&manifest).expect("serialize manifest");
    let result = compiled.validate(&payload);
    if let Err(errors) = result {
        let messages: Vec<String> = errors.map(|e| e.to_string()).collect();
        panic!("manifest with inference_parameters must validate: {messages:?}");
    }
}

#[test]
fn manifest_with_unknown_assertion_is_rejected() {
    let schema = load_schema();
    let compiled = JSONSchema::compile(&schema).expect("compile schema");
    let mut payload = serde_json::to_value(minimal_manifest()).expect("serialize manifest");
    payload["assertions"]["gemma.witness.unknown_extra"] = serde_json::json!("not allowed");
    let result = compiled.validate(&payload);
    assert!(
        result.is_err(),
        "schema must reject unknown assertions due to additionalProperties:false"
    );
}
