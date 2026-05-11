//! Typed errors raised by `witness-core`.

use std::path::PathBuf;

/// Errors produced by `witness-core` operations.
///
/// Each variant carries enough context (paths, IDs, sizes) for callers to act
/// on the failure without needing to re-derive what went wrong.
#[derive(Debug, thiserror::Error)]
pub enum WitnessCoreError {
    /// The incident report failed JSON serialization.
    #[error("incident report could not be serialized: {source}. ensure all string fields are valid utf-8.")]
    Serialize {
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
    #[error("schema file at {path:?} did not parse as JSON: {source}. validate the file with `jq`.")]
    SchemaParse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}
