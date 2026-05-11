//! SHA-256 helpers operating on raw file bytes.
//!
//! Hashing is always over what `std::fs::read` returns. No decoding, no
//! normalization. This is a hard invariant of the bundle format: the JS
//! verifier will recompute the same hash from the same bytes.

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::WitnessCoreError;

/// Compute `SHA-256(raw_bytes(path))` and return lowercase hex.
///
/// # Errors
/// Returns [`WitnessCoreError::AssetRead`] if the file at `path` cannot be
/// opened or fully read.
pub fn hash_file_hex(path: &Path) -> Result<String, WitnessCoreError> {
    let bytes = std::fs::read(path).map_err(|source| WitnessCoreError::AssetRead {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(hash_bytes_hex(&bytes))
}

/// Compute `SHA-256(bytes)` and return lowercase hex.
pub fn hash_bytes_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
