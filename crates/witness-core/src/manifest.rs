//! Manifest types matching `spec/manifest-schema.json`.
//!
//! These structs are the typed surface used throughout the capture app and
//! the round-trip verifier. They serialize via `serde_jcs::to_vec` for the
//! signing payload; field ordering in the source therefore does not affect
//! the wire bytes.

use serde::{Deserialize, Serialize};

use crate::assertions::incident_report::IncidentReport;
use crate::assertions::inference_parameters::InferenceParameters;

/// Current manifest schema version.
///
/// Verifiers route on this value, so any change to the manifest layout that
/// breaks an older verifier must bump this constant in lockstep with the
/// JSON Schema and the verifier's version routing table.
pub const MANIFEST_VERSION: u32 = 1;

/// Top-level signed document of a `.witness` bundle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub manifest_version: u32,
    pub bundle_id: String,
    pub created_at: String,
    pub signer: SignerInfo,
    pub assets: Vec<AssetEntry>,
    pub assertions: Assertions,
}

/// Signer metadata recorded inside the manifest itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerInfo {
    pub algorithm: String,
    pub public_key_pem: String,
    pub key_id: String,
}

/// One asset entry. `path` is the in-zip path, `sha256` is hex(SHA-256(raw bytes)).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetEntry {
    pub path: String,
    pub media_type: String,
    pub sha256: String,
    pub bytes: u64,
}

/// Namespaced assertions. Serde renames keep the wire form aligned with the
/// `gemma.witness.*` namespace used in the spec.
///
/// Optional assertions are skipped on serialize when absent, so existing
/// bundles remain byte-identical and verifiers that ignore them keep
/// working. The matching JSON Schema lists each optional field in
/// `properties` but not in `required`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Assertions {
    #[serde(rename = "gemma.witness.model_fingerprint")]
    pub model_fingerprint: ModelFingerprint,
    #[serde(rename = "gemma.witness.incident_report")]
    pub incident_report: IncidentReport,
    #[serde(rename = "gemma.witness.reasoning_trace")]
    pub reasoning_trace: ReasoningTrace,
    #[serde(rename = "gemma.witness.consistency_verdict")]
    pub consistency_verdict: ConsistencyVerdict,
    #[serde(rename = "gemma.witness.capture_environment")]
    pub capture_environment: CaptureEnvironment,
    #[serde(
        rename = "gemma.witness.inference_parameters",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub inference_parameters: Option<InferenceParameters>,
}

/// Identity of the model that produced the reasoning + structured report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelFingerprint {
    pub model_id: String,
    pub revision: String,
    pub sha256: String,
}

/// Pointer at the verbatim thinking-channel asset stored in the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReasoningTrace {
    pub asset_path: String,
    pub sha256: String,
    pub bytes: u64,
}

/// Gemma's audio/image consistency call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyVerdict {
    pub verdict: ConsistencyLabel,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub summary: Option<String>,
}

/// The two allowed verdict labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsistencyLabel {
    Consistent,
    Inconsistent,
}

/// Environment in which the bundle was sealed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureEnvironment {
    pub os: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub hostname: Option<String>,
    pub app_version: String,
    pub captured_at: String,
}

/// Detached signature document stored alongside the manifest inside the
/// `.witness` ZIP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureDocument {
    pub algorithm: String,
    pub key_id: String,
    pub signature_b64: String,
    pub signed_payload: String,
    pub canonicalization: String,
}
