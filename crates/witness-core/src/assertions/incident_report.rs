//! Incident report assertion.
//!
//! Mirrors `spec/incident-schema.json` exactly. Any change to one must be
//! reflected in the other; the round-trip test in
//! `crates/witness-core/tests/incident_schema.rs` enforces this.

use serde::{Deserialize, Serialize};

/// High-level category assigned to an incident.
///
/// The set is intentionally coarse: finer-grained taxonomies belong in the
/// `notes` field so the verifier does not need to grow its enum over time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IncidentType {
    /// Unsafe physical condition (slip hazard, exposed wiring, etc.).
    SafetyHazard,
    /// Pollution, spill, or other environmental harm.
    Environmental,
    /// Wage theft, unsafe working conditions, retaliation.
    Labor,
    /// Verbal, physical, or sexual harassment.
    Harassment,
    /// Damage to physical property.
    PropertyDamage,
    /// Anything that does not fit the above.
    Other,
}

/// Kind of evidence file referenced from the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Audio,
    Image,
    Video,
    Document,
    Other,
}

/// Reference to a binary asset by content hash.
///
/// The `sha256` is the hex-encoded SHA-256 of the raw bytes, computed by the
/// capture pipeline at the moment the asset was written to disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReference {
    /// Type of asset (audio, image, etc.).
    pub kind: EvidenceKind,
    /// Lowercase hex SHA-256 of the raw asset bytes.
    pub sha256: String,
}

/// Structured location of the incident.
///
/// `description` is required because it survives even when GPS is unavailable.
/// Coordinates are optional and bounded by Earth's geographic ranges.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Location {
    /// Latitude in decimal degrees, range `[-90, 90]`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[schemars(range(min = -90.0, max = 90.0))]
    pub lat: Option<f64>,
    /// Longitude in decimal degrees, range `[-180, 180]`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[schemars(range(min = -180.0, max = 180.0))]
    pub lng: Option<f64>,
    /// Free-text description of the location.
    #[schemars(length(min = 1))]
    pub description: String,
}

/// Optional contact information for the witness.
///
/// All fields are optional: the witness may choose to remain anonymous.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct WitnessContact {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[schemars(length(min = 1))]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[schemars(length(min = 1))]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[schemars(length(min = 1), email)]
    pub email: Option<String>,
}

/// A structured incident report.
///
/// This is the output of the inference pass that runs against a witness
/// transcript. The report is hashed and signed alongside the raw transcript
/// when the bundle is finalized.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IncidentReport {
    /// ISO 8601 timestamp of when the incident occurred (not when it was reported).
    pub timestamp: String,
    /// Where the incident occurred.
    pub location: Location,
    /// Optional contact for the witness.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub witness_contact: Option<WitnessContact>,
    /// Coarse category for triage.
    pub incident_type: IncidentType,
    /// Free-text summary, at least 20 characters.
    #[schemars(length(min = 20))]
    pub narrative_summary: String,
    /// Severity 1 (minor) to 5 (catastrophic).
    #[schemars(range(min = 1, max = 5))]
    pub severity: u8,
    /// Optional analyst notes.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub notes: Option<String>,
    /// Hash references to the raw evidence files.
    pub evidence_references: Vec<EvidenceReference>,
}
