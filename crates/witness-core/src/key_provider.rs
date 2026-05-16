//! Abstraction over signing-key backends.
//!
//! All callers in the capture app go through [`KeyProvider`] rather than
//! talking to `keystore.rs` directly. This isolates the rest of the codebase
//! from where the private key actually lives (OS keychain, TPM, Secure
//! Enclave) and lets future backends plug in without touching the seal path.
//!
//! Current shipping implementation:
//! - [`SoftwareEd25519Provider`]: Ed25519 seed in the OS keychain. Same wire
//!   format the project has shipped since Day 1.
//!
//! Reserved for hardware-backed backends (planned, not yet implemented):
//! - SecureEnclaveProvider on macOS using ECDSA P-256 via the SEP token.
//! - TpmProvider on Windows (ncrypt) and Linux (tpm2-tss), also P-256.
//!
//! When those land, [`SigningAlgorithm`] gains new variants and the manifest
//! spec bumps to `manifest_version=2` with a tagged `signer.algorithm` field.
//! Today the only allowed value is `ed25519`, matching the existing schema.

use std::sync::Mutex;

use ed25519_dalek::SigningKey;

use crate::error::WitnessCoreError;
use crate::keystore::load_or_create_signing_key;
use crate::signing::{encode_public_key_pem, key_id, sign};

/// Wire-level signing algorithm. Mirrors `signer.algorithm` in the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// PKCS#8 PEM Ed25519 public key, 64-byte signature.
    Ed25519,
}

impl SigningAlgorithm {
    /// Returns the wire string for this algorithm (the value stored in
    /// `signer.algorithm`).
    pub fn as_str(&self) -> &'static str {
        match self {
            SigningAlgorithm::Ed25519 => "ed25519",
        }
    }
}

/// What a key provider returns to callers that need to identify the signing
/// key (manifest builder, signature document writer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyHandle {
    pub algorithm: SigningAlgorithm,
    pub public_key_pem: String,
    pub key_id: String,
}

/// Provider of a signing key for the capture device.
///
/// Implementations must:
/// - Never expose private-key bytes through the public API.
/// - Be safe to call concurrently (the seal path can in theory be re-entered).
/// - Produce a signature that verifies against [`PublicKeyHandle::public_key_pem`]
///   using the algorithm reported by [`Self::algorithm`].
pub trait KeyProvider: Send + Sync {
    /// Generate a key on first call, or load the existing one. Returns only
    /// the public-key surface, never the private bytes.
    fn load_or_create_public(&self) -> Result<PublicKeyHandle, WitnessCoreError>;

    /// Sign `payload` and return the raw signature bytes. Length depends on
    /// the algorithm (64 for Ed25519, ~71 DER-encoded for ECDSA P-256).
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, WitnessCoreError>;

    /// Algorithm this provider's signatures use.
    fn algorithm(&self) -> SigningAlgorithm;
}

/// Default provider: Ed25519 seed in the OS keychain.
///
/// This is the implementation the capture app has shipped since Day 1. It is
/// software-only; the README's "Trust model limitations" section accurately
/// describes the threat model. Future hardware-backed providers will live
/// next to this one and the seal command will pick at runtime.
#[derive(Debug, Default)]
pub struct SoftwareEd25519Provider {
    cached_key: Mutex<Option<SigningKey>>,
}

impl SoftwareEd25519Provider {
    pub fn new() -> Self {
        Self::default()
    }

    fn with_key<T>(
        &self,
        f: impl FnOnce(&SigningKey) -> Result<T, WitnessCoreError>,
    ) -> Result<T, WitnessCoreError> {
        let mut guard = self
            .cached_key
            .lock()
            .map_err(|err| WitnessCoreError::Keyring {
                detail: format!("device key cache lock poisoned: {err}"),
            })?;
        if guard.is_none() {
            *guard = Some(load_or_create_signing_key()?);
        }
        let key = guard.as_ref().ok_or_else(|| WitnessCoreError::Keyring {
            detail: "device key cache was empty after load".to_string(),
        })?;
        f(key)
    }
}

impl KeyProvider for SoftwareEd25519Provider {
    fn load_or_create_public(&self) -> Result<PublicKeyHandle, WitnessCoreError> {
        self.with_key(|key| {
            let verifying = key.verifying_key();
            Ok(PublicKeyHandle {
                algorithm: SigningAlgorithm::Ed25519,
                public_key_pem: encode_public_key_pem(&verifying)?,
                key_id: key_id(&verifying),
            })
        })
    }

    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, WitnessCoreError> {
        self.with_key(|key| Ok(sign(key, payload).to_bytes().to_vec()))
    }

    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Ed25519
    }
}

/// Marker stub for the planned hardware-backed providers.
///
/// Compilation under the `hardware-keys` feature is intentionally not yet
/// wired up; enabling it will surface a build-time error that points at this
/// module so a maintainer cannot accidentally ship a binary that claims
/// hardware backing without delivering it. When the SEP and TPM impls land,
/// each will live behind its own `#[cfg(target_os = "...")]` block here.
#[cfg(feature = "hardware-keys")]
mod hardware {
    compile_error!(
        "the `hardware-keys` feature is reserved for a future Secure-Enclave / TPM backend. \
         the corresponding `KeyProvider` implementations are not yet wired up. \
         build without --features hardware-keys, or contribute the missing backend."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_algorithm_wire_string_is_stable() {
        assert_eq!(SigningAlgorithm::Ed25519.as_str(), "ed25519");
    }

    #[test]
    fn software_provider_reports_ed25519() {
        let provider = SoftwareEd25519Provider::new();
        assert_eq!(provider.algorithm(), SigningAlgorithm::Ed25519);
    }
}
