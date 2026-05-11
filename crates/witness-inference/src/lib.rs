//! HTTP client for the local OpenAI-compatible inference sidecar, plus the
//! per-pass modules that compose into a full multimodal pipeline.

mod client;
mod error;
mod http;
pub mod passes;
mod response;

pub use client::{
    structure_incident, structure_incident_with, InferenceClient, StructureOutcome,
    DEFAULT_MAX_RETRIES, DEFAULT_TEMPERATURE, DEFAULT_TOP_P,
};
pub use error::InferenceError;
pub use http::{DEFAULT_ENDPOINT, DEFAULT_MODEL};
pub use passes::transcribe::{transcribe, TranscribeOutcome};
