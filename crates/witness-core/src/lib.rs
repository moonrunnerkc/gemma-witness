//! Core types and schemas for Gemma.Witness.
//!
//! This crate owns the canonical data model: the incident report, the
//! manifest (added in later passes), and the typed errors raised when those
//! values fail validation.

pub mod assertions;
pub mod bundle_builder;
pub mod bundle_zip;
pub mod canonical;
pub mod error;
pub mod hashing;
pub mod keystore;
pub mod manifest;
pub mod signing;
pub mod verifier;

pub use assertions::incident_report::{
    EvidenceKind, EvidenceReference, IncidentReport, IncidentType, Location, WitnessContact,
};
pub use bundle_builder::{build_and_seal_bundle, BundleInputs, BundleSigner};
pub use error::WitnessCoreError;
pub use manifest::{
    Assertions, AssetEntry, CaptureEnvironment, ConsistencyLabel, ConsistencyVerdict, Manifest,
    ModelFingerprint, ReasoningTrace, SignatureDocument, SignerInfo, MANIFEST_VERSION,
};
pub use verifier::{verify_bundle, VerificationReport};
