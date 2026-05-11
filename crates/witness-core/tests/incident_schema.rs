//! Round-trip tests for the incident report against `spec/incident-schema.json`.

use jsonschema::JSONSchema;
use serde_json::json;
use witness_core::{
    EvidenceKind, EvidenceReference, IncidentReport, IncidentType, Location, WitnessContact,
};

fn load_spec_schema() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../spec/incident-schema.json");
    let raw = std::fs::read_to_string(path).expect("spec/incident-schema.json must be readable");
    serde_json::from_str(&raw).expect("spec/incident-schema.json must parse as JSON")
}

fn sample_report() -> IncidentReport {
    IncidentReport {
        timestamp: "2026-05-10T21:00:00Z".to_string(),
        location: Location {
            lat: Some(37.7749),
            lng: Some(-122.4194),
            description: "Corner of Main St and Oak Ave".to_string(),
        },
        witness_contact: Some(WitnessContact {
            name: Some("Jane Doe".to_string()),
            phone: None,
            email: Some("jane@example.org".to_string()),
        }),
        incident_type: IncidentType::SafetyHazard,
        narrative_summary: "A worker slipped on an unmarked wet floor near the loading dock."
            .to_string(),
        severity: 3,
        notes: None,
        evidence_references: vec![EvidenceReference {
            kind: EvidenceKind::Audio,
            sha256: "a".repeat(64),
        }],
    }
}

#[test]
fn sample_report_validates_against_spec() {
    let schema = load_spec_schema();
    let validator = JSONSchema::compile(&schema).expect("spec schema must compile");
    let report = sample_report();
    let value = serde_json::to_value(&report).expect("report must serialize");
    let result = validator.validate(&value);
    assert!(
        result.is_ok(),
        "sample report should validate against spec, errors: {}",
        result
            .err()
            .map(|errs| errs.map(|e| e.to_string()).collect::<Vec<_>>().join("; "))
            .unwrap_or_default()
    );
}

#[test]
fn report_round_trips_through_json() {
    let report = sample_report();
    let value = serde_json::to_value(&report).expect("serialize");
    let back: IncidentReport = serde_json::from_value(value).expect("deserialize");
    assert_eq!(report, back);
}

#[test]
fn rejects_short_narrative() {
    let schema = load_spec_schema();
    let validator = JSONSchema::compile(&schema).expect("spec schema must compile");
    let bad = json!({
        "timestamp": "2026-05-10T21:00:00Z",
        "location": {"description": "X"},
        "incident_type": "other",
        "narrative_summary": "too short",
        "severity": 1,
        "evidence_references": []
    });
    assert!(validator.validate(&bad).is_err());
}

#[test]
fn rejects_unknown_incident_type() {
    let schema = load_spec_schema();
    let validator = JSONSchema::compile(&schema).expect("spec schema must compile");
    let bad = json!({
        "timestamp": "2026-05-10T21:00:00Z",
        "location": {"description": "Loading dock"},
        "incident_type": "ufo_sighting",
        "narrative_summary": "A long enough narrative summary string here.",
        "severity": 1,
        "evidence_references": []
    });
    assert!(validator.validate(&bad).is_err());
}

#[test]
fn rejects_additional_properties() {
    let schema = load_spec_schema();
    let validator = JSONSchema::compile(&schema).expect("spec schema must compile");
    let bad = json!({
        "timestamp": "2026-05-10T21:00:00Z",
        "location": {"description": "Loading dock"},
        "incident_type": "other",
        "narrative_summary": "A long enough narrative summary string here.",
        "severity": 1,
        "evidence_references": [],
        "extra_field": "nope"
    });
    assert!(validator.validate(&bad).is_err());
}
