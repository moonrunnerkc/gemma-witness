//! Core types and schemas for Gemma.Witness.
//!
//! This crate owns the canonical data model: the incident report, the
//! manifest (added in later passes), and the typed errors raised when those
//! values fail validation.

pub mod assertions;
pub mod error;

pub use assertions::incident_report::{
    EvidenceKind, EvidenceReference, IncidentReport, IncidentType, Location, WitnessContact,
};
pub use error::WitnessCoreError;
