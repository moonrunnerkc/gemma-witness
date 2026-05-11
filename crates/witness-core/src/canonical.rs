//! RFC 8785 JSON Canonicalization Scheme helpers.
//!
//! Every signing operation in this crate goes through [`canonicalize`] so
//! that the signature is over a deterministic byte sequence. The matching
//! JS verifier produces the same bytes from the same logical manifest.

use serde::Serialize;

use crate::error::WitnessCoreError;

/// Canonicalize `value` per RFC 8785 (JCS) and return the resulting bytes.
///
/// # Errors
/// Returns [`WitnessCoreError::Canonicalize`] if the value cannot be encoded.
/// This is rare in practice (it implies a non-finite float or a map with
/// non-string keys), but never an `unwrap`-grade impossibility.
pub fn canonicalize<T: Serialize>(value: &T) -> Result<Vec<u8>, WitnessCoreError> {
    serde_jcs::to_vec(value).map_err(|source| WitnessCoreError::Canonicalize { source })
}
