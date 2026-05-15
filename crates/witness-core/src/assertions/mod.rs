//! Typed assertions that may appear inside a witness manifest.
//!
//! Each submodule defines one assertion shape with a typed Rust struct that
//! mirrors the JSON Schema in `spec/`. Adding a new assertion type means
//! adding a new module here and wiring it into the verifier.

pub mod audio_fingerprint;
pub mod incident_report;
pub mod inference_parameters;
