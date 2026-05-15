//! Optional advisory assertion that records the sampling parameters used
//! by each inference pass.
//!
//! The data is forensic, not cryptographic: it lets an offline analyst run
//! the same model with the same parameters and check whether the embedded
//! reasoning trace is a plausible draw for this configuration. It is not a
//! check the verifier can pass or fail on its own.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Top-level optional assertion. Serialized to the `gemma.witness.inference_parameters`
/// key when present, omitted entirely when absent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InferenceParameters {
    /// Per-pass parameters keyed by pass name. Lexicographic key ordering
    /// drops out of JCS canonicalization at sign time.
    pub passes: BTreeMap<String, PassParameters>,
    /// Sampling RNG seed if one was pinned. None today across every pass; the
    /// field exists so a later release can pin a seed without a schema bump.
    pub sampling_seed: Option<u64>,
    /// Human-readable advisory note repeated inside the field itself so a
    /// reviewer pulling raw JSON sees the disclaimer alongside the data.
    pub note: String,
}

/// Parameters for one pass.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PassParameters {
    pub temperature: f32,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub top_p: Option<f32>,
    pub max_tokens: u32,
    /// Gemma 4 visual token budget. Only meaningful for image-conditioned
    /// passes; omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub visual_token_budget: Option<u32>,
    /// SHA-256 (lowercase hex) of the fixed instruction prompt the pass uses.
    /// User content (transcript, image bytes, report) is excluded because it
    /// is already pinned elsewhere in the manifest.
    pub prompt_sha256: String,
}
