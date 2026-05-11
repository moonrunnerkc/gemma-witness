//! Typed errors raised by `witness-core`.

use std::path::PathBuf;

/// Errors produced by `witness-core` operations.
///
/// Each variant carries enough context (paths, IDs, sizes) for callers to act
/// on the failure without needing to re-derive what went wrong.
#[derive(Debug, thiserror::Error)]
pub enum WitnessCoreError {
    /// JSON serialization or deserialization failed.
    #[error("witness-core json codec failure: {source}. inspect the offending value with serde_json::to_string_pretty.")]
    Serialize {
        #[source]
        source: serde_json::Error,
    },

    /// RFC 8785 canonicalization failed.
    #[error("manifest could not be canonicalized per RFC 8785: {source}. check for non-finite floats or non-string map keys.")]
    Canonicalize {
        #[source]
        source: serde_json::Error,
    },

    /// A schema file on disk could not be read.
    #[error("schema file at {path:?} could not be read: {source}. confirm the file exists and is readable.")]
    SchemaRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// A schema file on disk did not parse as JSON.
    #[error(
        "schema file at {path:?} did not parse as JSON: {source}. validate the file with `jq`."
    )]
    SchemaParse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    /// A captured asset on disk could not be read.
    #[error("asset at {path:?} could not be read: {source}. confirm the capture pipeline wrote the file before sealing.")]
    AssetRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// An image path had an unsupported or missing extension.
    #[error("image at {path:?} is not usable: {detail}")]
    UnsupportedImage { path: PathBuf, detail: String },

    /// Writing the bundle ZIP failed.
    #[error("zip write failed for {path:?}: {detail}: {source}")]
    ZipWrite {
        path: PathBuf,
        detail: String,
        #[source]
        source: std::io::Error,
    },

    /// Reading the bundle ZIP failed.
    #[error("zip read failed for {path:?}: {detail}: {source}")]
    ZipRead {
        path: PathBuf,
        detail: String,
        #[source]
        source: std::io::Error,
    },

    /// The bundle is missing a required entry.
    #[error("bundle structure invalid: {detail}")]
    BundleStructure { detail: String },

    /// The provided PEM-encoded public key could not be parsed.
    #[error("public key PEM did not parse: {detail}. expected PKCS#8 PEM for an Ed25519 key.")]
    BadPublicKey { detail: String },

    /// Encoding a public key to PEM failed.
    #[error("could not PEM-encode public key: {detail}")]
    PublicKeyEncode { detail: String },

    /// The signature did not match the manifest payload under the embedded key.
    #[error(
        "manifest signature verification failed: signature does not match canonicalized payload"
    )]
    SignatureInvalid,

    /// OS keychain operation failed.
    #[error("keychain operation failed: {detail}. on macOS open Keychain Access and confirm service tech.aftermath.gemma-witness is reachable.")]
    Keyring { detail: String },

    /// Caller asked to use the device key but none has been generated yet.
    #[error(
        "no device key has been generated. call load_or_create_device_key once before signing."
    )]
    NoDeviceKey,
}
