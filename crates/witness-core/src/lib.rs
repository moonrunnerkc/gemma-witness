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
pub mod key_provider;
pub mod keystore;
pub mod keystore_p256;
pub mod manifest;
pub mod signing;
pub mod signing_ecdsa;
pub mod verifier;

pub use assertions::audio_fingerprint::{
    self, compute as compute_audio_fingerprint, verify_against as verify_audio_fingerprint,
    AcousticCheck, AudioFingerprint,
};
pub use assertions::incident_report::{
    EvidenceKind, EvidenceReference, IncidentReport, IncidentType, Location, WitnessContact,
};
pub use assertions::inference_parameters::{InferenceParameters, PassParameters};
pub use bundle_builder::{build_and_seal_bundle, BundleInputs, BundleSigner};
pub use error::WitnessCoreError;
pub use key_provider::{KeyProvider, PublicKeyHandle, SigningAlgorithm, SoftwareEd25519Provider};
pub use manifest::{
    AmendsReference, Assertions, AssetEntry, CaptureEnvironment, ConsistencyLabel,
    ConsistencyVerdict, Manifest, ModelFingerprint, ReasoningTrace, SignatureDocument,
    SignerAttestation, SignerInfo, MANIFEST_VERSION,
};
pub use verifier::{verify_amendment_chain, verify_bundle, KnownFingerprint, VerificationReport};
