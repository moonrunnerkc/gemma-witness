//! HTTP client for the local OpenAI-compatible inference sidecar.

mod client;
mod error;
mod response;

pub use client::{
    structure_incident, structure_incident_with, InferenceClient, StructureOutcome,
    DEFAULT_ENDPOINT, DEFAULT_MAX_RETRIES, DEFAULT_MODEL, DEFAULT_TEMPERATURE, DEFAULT_TOP_P,
};
pub use error::InferenceError;
