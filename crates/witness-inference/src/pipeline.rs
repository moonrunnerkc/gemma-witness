//! End-to-end multimodal pipeline composition.
//!
//! Wires pass 0 (transcribe), pass 1 (structure), pass 2 (per-image
//! description), and pass 3 (consistency verdict) into a single
//! [`run_full_pipeline`] entry point.

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;
use witness_core::IncidentReport;

use crate::client::{InferenceClient, StructureOutcome};
use crate::error::InferenceError;
use crate::http::DEFAULT_ENDPOINT;
use crate::passes::analyze_image::{analyze_image, ImageAnalysis};
use crate::passes::check_consistency::{check_consistency, ConsistencyOutcome};
use crate::passes::transcribe::{transcribe, TranscribeOutcome};

/// Result of the full four-pass pipeline.
#[derive(Debug, Clone, Serialize)]
pub struct PipelineResult {
    /// Output of pass 0.
    pub transcribe: TranscribeOutcome,
    /// Output of pass 1.
    pub structure: StructureOutcomeSerde,
    /// Output of pass 2, one entry per input image, in submission order.
    pub images: Vec<ImageAnalysis>,
    /// Output of pass 3.
    pub consistency: ConsistencyOutcome,
    /// Total wall-clock latency across all passes, in milliseconds.
    pub total_latency_ms: u128,
}

/// Serialisable mirror of [`StructureOutcome`] that exposes only the parts
/// the manifest needs. The internal `StructureOutcome` is not [`Serialize`]
/// directly because [`IncidentReport`] lives in `witness-core`.
#[derive(Debug, Clone, Serialize)]
pub struct StructureOutcomeSerde {
    /// The validated structured incident report.
    pub report: IncidentReport,
    /// Retries used in pass 1.
    pub retries_used: u32,
    /// Pass-1 latency in milliseconds.
    pub latency_ms: u128,
}

impl From<StructureOutcome> for StructureOutcomeSerde {
    fn from(value: StructureOutcome) -> Self {
        Self {
            report: value.report,
            retries_used: value.retries_used,
            latency_ms: value.latency_ms,
        }
    }
}

/// Run the full pipeline against `audio_path` plus `image_paths`.
///
/// `schema` is the compiled JSON Schema document used to constrain the
/// pass-1 structuring output. Callers typically load it from
/// `spec/incident-schema.json`.
///
/// # Errors
///
/// Surfaces the first [`InferenceError`] from any pass. Image pass 2 runs
/// sequentially so that a transient failure on one image does not waste
/// sidecar time on the rest.
pub async fn run_full_pipeline(
    audio_path: &Path,
    image_paths: &[PathBuf],
    schema: &Value,
    endpoint: &str,
) -> Result<PipelineResult, InferenceError> {
    let started = std::time::Instant::now();
    let transcribe_outcome = transcribe(audio_path, endpoint).await?;

    let client = InferenceClient::with_endpoint(endpoint)?;
    let structure_outcome = client
        .structure_incident(&transcribe_outcome.transcript, schema)
        .await?;

    let mut images: Vec<ImageAnalysis> = Vec::with_capacity(image_paths.len());
    for image_path in image_paths {
        let analysis = analyze_image(image_path, endpoint).await?;
        images.push(analysis);
    }

    let descriptions: Vec<String> = images.iter().map(|i| i.description.clone()).collect();
    let consistency = check_consistency(
        &transcribe_outcome.transcript,
        &structure_outcome.report,
        &descriptions,
        endpoint,
    )
    .await?;

    Ok(PipelineResult {
        transcribe: transcribe_outcome,
        structure: structure_outcome.into(),
        images,
        consistency,
        total_latency_ms: started.elapsed().as_millis(),
    })
}

/// Convenience wrapper that targets the default sidecar endpoint.
pub async fn run_full_pipeline_default(
    audio_path: &Path,
    image_paths: &[PathBuf],
    schema: &Value,
) -> Result<PipelineResult, InferenceError> {
    run_full_pipeline(audio_path, image_paths, schema, DEFAULT_ENDPOINT).await
}
