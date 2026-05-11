//! HTTP client for the local OpenAI-compatible inference sidecar.

mod client;
mod error;
mod http;
mod response;

pub use client::{
    structure_incident, structure_incident_with, InferenceClient, StructureOutcome,
    DEFAULT_MAX_RETRIES, DEFAULT_TEMPERATURE, DEFAULT_TOP_P,
};
pub use error::InferenceError;
pub use http::{DEFAULT_ENDPOINT, DEFAULT_MODEL};
