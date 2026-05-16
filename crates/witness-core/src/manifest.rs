//! Manifest types matching `spec/manifest-schema.json`.
//!
//! These structs are the typed surface used throughout the capture app and
//! the round-trip verifier. They serialize via `serde_jcs::to_vec` for the
//! signing payload; field ordering in the source therefore does not affect
//! the wire bytes.

use serde::{Deserialize, Serialize};

use crate::assertions::audio_fingerprint::AudioFingerprint;
use crate::assertions::incident_report::IncidentReport;
use crate::assertions::inference_parameters::InferenceParameters;

/// Current manifest schema version produced by this build of the seal path.
///
/// Verifiers route on this value; bundles produced by this binary will carry
/// this value. The verifier accepts every value in
/// [`crate::verifier::SUPPORTED_MANIFEST_VERSIONS`], which is a superset of
/// the version emitted at seal time. Today the seal path still emits v1 with
/// Ed25519; v2 (which widens `signer.algorithm` to `ecdsa-p256` and adds an
/// optional `signer.attestation` blob) is parseable on the verify side ahead
/// of the hardware-backed signing providers that will produce it.
pub const MANIFEST_VERSION: u32 = 1;

/// Top-level signed document of a `.witness` bundle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub manifest_version: u32,
    pub bundle_id: String,
    pub created_at: String,
    pub signer: SignerInfo,
    pub assets: Vec<AssetEntry>,
    pub assertions: Assertions,
    /// Optional pointer at the bundle this one supersedes. The verifier
    /// surfaces the relationship; it does not merge bundles or hide the
    /// original. Cryptographically you cannot unsign, so corrections must
    /// be issued as new signed bundles that reference the prior one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub amends: Option<AmendsReference>,
}

/// Reference to a prior bundle that this manifest corrects or supersedes.
///
/// `original_signer_key_id` binds the amendment to the original signer.
/// Without it, anyone with their own valid key could sign an "amendment" of
/// any other person's bundle. Verifiers MUST refuse to treat an amendment as
/// a continuation of the chain when the amending bundle's
/// `signer.key_id` does not match this field. Renderers SHOULD surface the
/// mismatch prominently rather than silently downgrading the link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AmendsReference {
    /// UUID v4 of the original bundle.
    pub original_bundle_id: String,
    /// Hex SHA-256 of the original bundle's JCS-canonicalized manifest.
    pub original_manifest_sha256: String,
    /// `signer.key_id` of the original bundle. The amending bundle's
    /// `signer.key_id` must equal this value for the amendment chain to be
    /// trusted.
    pub original_signer_key_id: String,
    /// One-paragraph explanation of why this bundle amends the original.
    pub reason: String,
}

/// Signer metadata recorded inside the manifest itself.
///
/// `attestation` is reserved for v2+ manifests produced by a hardware-backed
/// key provider (Secure Enclave, TPM 2.0, NCrypt). It is `Option` and skipped
/// at serialize time when absent, so v1 bundles continue to round-trip byte-
/// for-byte. Verifiers must reject v1 manifests that carry the field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerInfo {
    pub algorithm: String,
    pub public_key_pem: String,
    pub key_id: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attestation: Option<SignerAttestation>,
}

/// Hardware-backed key attestation blob carried by v2 manifests.
///
/// The verifier surfaces the format tag and the base64 payload to the UI; it
/// does not by itself gate verification on the blob's contents. A future
/// pinning policy (per signer identity, per format) may opt to require a
/// specific attestation format, but in WS3-1 the field is informational.
///
/// Known `format` values:
/// - `apple-sep-v1`: Apple Secure Enclave attestation (the data returned by
///   `SecKeyCreateAttestation`).
/// - `tpm2-quote-v1`: TPM 2.0 `TPM2_Quote` + `TPM2_Certify` pair, packed.
/// - `ncrypt-v1`: Windows NCrypt platform-key attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerAttestation {
    pub format: String,
    pub payload_b64: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub certificate_chain_b64: Option<Vec<String>>,
}

/// One asset entry. `path` is the in-zip path, `sha256` is hex(SHA-256(raw bytes)).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    #[serde(
        rename = "gemma.witness.audio_fingerprint",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub audio_fingerprint: Option<AudioFingerprint>,
}

/// Identity of the model that produced the reasoning + structured report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelFingerprint {
    pub model_id: String,
    pub revision: String,
    pub sha256: String,
}

/// Pointer at the verbatim thinking-channel asset stored in the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReasoningTrace {
    pub asset_path: String,
    pub sha256: String,
    pub bytes: u64,
}

/// Gemma's audio/image consistency call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct SignatureDocument {
    pub algorithm: String,
    pub key_id: String,
    pub signature_b64: String,
    pub signed_payload: String,
    pub canonicalization: String,
}
