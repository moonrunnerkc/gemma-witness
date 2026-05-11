//! HTTP client for the local OpenAI-compatible inference sidecar, plus the
//! per-pass modules that compose into a full multimodal pipeline.

mod client;
mod error;
mod http;
pub mod passes;
mod pipeline;
mod response;

pub use client::{
    structure_incident, structure_incident_with, InferenceClient, StructureOutcome,
    DEFAULT_MAX_RETRIES, DEFAULT_TEMPERATURE, DEFAULT_TOP_P,
};
pub use error::InferenceError;
pub use http::{DEFAULT_ENDPOINT, DEFAULT_MODEL};
pub use passes::analyze_image::{
    analyze_image, analyze_image_with_budget, ImageAnalysis, DEFAULT_VISUAL_TOKEN_BUDGET,
};
pub use passes::check_consistency::{check_consistency, ConsistencyOutcome, ALLOWED_VERDICTS};
pub use passes::transcribe::{transcribe, TranscribeOutcome};
pub use pipeline::{run_full_pipeline, run_full_pipeline_default, PipelineResult, StructureOutcomeSerde};
