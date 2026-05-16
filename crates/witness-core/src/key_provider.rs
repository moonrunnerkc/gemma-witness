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
//! Hardware-backed backend (behind `--features hardware-keys`):
//! - [`crate::secure_enclave::SecureEnclaveProvider`] on macOS, using ECDSA
//!   P-256 routed through the Secure Enclave token.
//!
//! Reserved for future targets (not yet implemented):
//! - TpmProvider on Linux (tpm2-tss), P-256 again.
//! - WindowsPlatformKeyProvider on Windows (ncrypt), P-256.

use std::sync::Mutex;

use ed25519_dalek::SigningKey;

use crate::error::WitnessCoreError;
use crate::keystore::load_or_create_signing_key;
use crate::keystore_p256::load_or_create_signing_key as load_or_create_p256_signing_key;
use crate::signing::{encode_public_key_pem, key_id, sign};
use crate::signing_ecdsa;

/// Wire-level signing algorithm. Mirrors `signer.algorithm` in the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// PKCS#8 PEM Ed25519 public key, 64-byte raw signature. Permitted in
    /// every manifest version.
    Ed25519,
    /// SPKI PEM ECDSA P-256 public key, ASN.1/DER-encoded signature
    /// (variable length, typically 70 to 72 bytes). Permitted from
    /// `manifest_version >= 2`. Matches the curve and encoding that Apple
    /// Secure Enclave, TPM 2.0, and Windows NCrypt produce natively.
    EcdsaP256,
}

impl SigningAlgorithm {
    /// Returns the wire string for this algorithm (the value stored in
    /// `signer.algorithm`).
    pub fn as_str(&self) -> &'static str {
        match self {
            SigningAlgorithm::Ed25519 => "ed25519",
            SigningAlgorithm::EcdsaP256 => "ecdsa-p256",
        }
    }

    /// The lowest `manifest_version` that may carry a signer using this
    /// algorithm. v1 manifests are Ed25519-only; v2 widens to P-256.
    pub fn minimum_manifest_version(&self) -> u32 {
        match self {
            SigningAlgorithm::Ed25519 => 1,
            SigningAlgorithm::EcdsaP256 => 2,
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

/// Software-backed ECDSA P-256 provider.
///
/// Parallel to [`SoftwareEd25519Provider`]. The 32-byte private scalar lives
/// in the OS keychain under a distinct service+account from the Ed25519
/// entry, so the two providers can coexist on the same host. This provider
/// is a stepping stone toward the hardware-backed P-256 providers (Secure
/// Enclave, TPM 2.0, Windows NCrypt) that ship behind the `hardware-keys`
/// feature. Use it for local development, CI, and tests; ship hardware.
#[derive(Debug, Default)]
pub struct SoftwareEcdsaP256Provider {
    cached_key: Mutex<Option<p256::ecdsa::SigningKey>>,
}

impl SoftwareEcdsaP256Provider {
    pub fn new() -> Self {
        Self::default()
    }

    fn with_key<T>(
        &self,
        f: impl FnOnce(&p256::ecdsa::SigningKey) -> Result<T, WitnessCoreError>,
    ) -> Result<T, WitnessCoreError> {
        let mut guard = self
            .cached_key
            .lock()
            .map_err(|err| WitnessCoreError::Keyring {
                detail: format!("P-256 device key cache lock poisoned: {err}"),
            })?;
        if guard.is_none() {
            *guard = Some(load_or_create_p256_signing_key()?);
        }
        let key = guard.as_ref().ok_or_else(|| WitnessCoreError::Keyring {
            detail: "P-256 device key cache was empty after load".to_string(),
        })?;
        f(key)
    }
}

impl KeyProvider for SoftwareEcdsaP256Provider {
    fn load_or_create_public(&self) -> Result<PublicKeyHandle, WitnessCoreError> {
        self.with_key(|key| {
            let verifying = key.verifying_key();
            Ok(PublicKeyHandle {
                algorithm: SigningAlgorithm::EcdsaP256,
                public_key_pem: signing_ecdsa::encode_public_key_pem(verifying)?,
                key_id: signing_ecdsa::key_id(verifying),
            })
        })
    }

    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, WitnessCoreError> {
        self.with_key(|key| Ok(signing_ecdsa::sign(key, payload)))
    }

    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::EcdsaP256
    }
}

// Per-target gating for the `hardware-keys` feature. Each supported target
// pulls in its own backend module from a sibling file; targets without a
// backend yet (Linux TPM, Windows NCrypt) still produce a build-time error
// so a maintainer cannot accidentally ship a binary that claims hardware
// backing without delivering it.
#[cfg(all(feature = "hardware-keys", not(any(target_os = "macos"))))]
compile_error!(
    "the `hardware-keys` feature is currently implemented for macOS (Secure Enclave) only. \
     Linux (TPM 2.0) and Windows (NCrypt) backends are tracked but not yet wired up. \
     build without --features hardware-keys on this target, or contribute the missing backend."
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_algorithm_wire_string_is_stable() {
        assert_eq!(SigningAlgorithm::Ed25519.as_str(), "ed25519");
        assert_eq!(SigningAlgorithm::EcdsaP256.as_str(), "ecdsa-p256");
    }

    #[test]
    fn signing_algorithm_minimum_manifest_version_matches_spec() {
        assert_eq!(SigningAlgorithm::Ed25519.minimum_manifest_version(), 1);
        assert_eq!(SigningAlgorithm::EcdsaP256.minimum_manifest_version(), 2);
    }

    #[test]
    fn software_provider_reports_ed25519() {
        let provider = SoftwareEd25519Provider::new();
        assert_eq!(provider.algorithm(), SigningAlgorithm::Ed25519);
    }

    #[test]
    fn software_p256_provider_reports_ecdsa_p256() {
        let provider = SoftwareEcdsaP256Provider::new();
        assert_eq!(provider.algorithm(), SigningAlgorithm::EcdsaP256);
    }
}
