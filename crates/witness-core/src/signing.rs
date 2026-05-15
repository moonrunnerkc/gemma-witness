//! Ed25519 signing and verification.
//!
//! Public keys are exported as PKCS#8 PEM. Private key material never
//! leaves this module's call boundary: callers pass in a [`SigningKey`]
//! handle (or fetch one from [`crate::keystore`]) and receive a
//! [`Signature`] back. The bytes of the private scalar are not exposed by
//! the public API.

use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::WitnessCoreError;

/// Generate a fresh Ed25519 signing key from the OS CSPRNG.
pub fn generate_signing_key() -> SigningKey {
    let mut csprng = rand::rngs::OsRng;
    SigningKey::generate(&mut csprng)
}

/// Sign `payload` with `key`, returning the raw 64-byte signature.
pub fn sign(key: &SigningKey, payload: &[u8]) -> Signature {
    key.sign(payload)
}

/// Verify `signature_bytes` against `payload` using the PKCS#8 PEM `public_key_pem`.
///
/// Uses strict RFC 8032 verification: rejects signatures with non-canonical
/// `s` scalars (malleability) and rejects R points in a small torsion
/// subgroup. This is the verification path other strict-mode third-party
/// verifiers will use; matching that behavior here closes cross-verifier
/// drift on the same bytes.
///
/// # Errors
/// Returns [`WitnessCoreError::BadPublicKey`] if the PEM does not parse, or
/// [`WitnessCoreError::SignatureInvalid`] if the signature does not match
/// or fails strict canonical-form checks.
pub fn verify_pem(
    public_key_pem: &str,
    payload: &[u8],
    signature_bytes: &[u8; 64],
) -> Result<(), WitnessCoreError> {
    let verifying = parse_public_key_pem(public_key_pem)?;
    let signature = Signature::from_bytes(signature_bytes);
    verifying
        .verify_strict(payload, &signature)
        .map_err(|_| WitnessCoreError::SignatureInvalid)
}

/// Parse a PKCS#8 PEM-encoded Ed25519 public key.
///
/// # Errors
/// Returns [`WitnessCoreError::BadPublicKey`] when the PEM cannot be decoded.
pub fn parse_public_key_pem(public_key_pem: &str) -> Result<VerifyingKey, WitnessCoreError> {
    use ed25519_dalek::pkcs8::DecodePublicKey;
    VerifyingKey::from_public_key_pem(public_key_pem).map_err(|source| {
        WitnessCoreError::BadPublicKey {
            detail: source.to_string(),
        }
    })
}

/// Encode a [`VerifyingKey`] as PKCS#8 PEM (LF line endings).
///
/// # Errors
/// Returns [`WitnessCoreError::PublicKeyEncode`] if encoding fails.
pub fn encode_public_key_pem(verifying: &VerifyingKey) -> Result<String, WitnessCoreError> {
    verifying
        .to_public_key_pem(LineEnding::LF)
        .map_err(|source| WitnessCoreError::PublicKeyEncode {
            detail: source.to_string(),
        })
}

/// Compute the canonical key ID: lowercase hex SHA-256 of the 32-byte raw
/// public key.
pub fn key_id(verifying: &VerifyingKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifying.as_bytes());
    hex::encode(hasher.finalize())
}
