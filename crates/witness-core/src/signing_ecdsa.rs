//! ECDSA P-256 signing and verification.
//!
//! Parallel to [`crate::signing`] (Ed25519). Public keys are exported as
//! SubjectPublicKeyInfo PEM per RFC 5480, matching what `openssl ec -pubout`
//! and the macOS Security framework emit. Signatures are ASN.1/DER-encoded
//! (variable length, typically 70 to 72 bytes), matching the encoding the
//! Secure Enclave and TPM 2.0 produce natively.
//!
//! Private key material never leaves this module's call boundary: callers
//! pass in a [`p256::ecdsa::SigningKey`] handle (or fetch one from
//! [`crate::keystore_p256`]) and receive raw DER signature bytes back.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::der::pem::LineEnding;
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use p256::PublicKey;
use sha2::{Digest, Sha256};

use crate::error::WitnessCoreError;

/// Generate a fresh ECDSA P-256 signing key from the OS CSPRNG.
pub fn generate_signing_key() -> SigningKey {
    let mut rng = rand::rngs::OsRng;
    SigningKey::random(&mut rng)
}

/// Sign `payload` with `key`, returning the ASN.1/DER-encoded signature.
///
/// DER signatures are variable length (typically 70 to 72 bytes). Callers
/// must not assume a fixed size.
pub fn sign(key: &SigningKey, payload: &[u8]) -> Vec<u8> {
    let signature: Signature = key.sign(payload);
    signature.to_der().as_bytes().to_vec()
}

/// Verify a DER-encoded ECDSA P-256 signature against `payload` using the
/// SubjectPublicKeyInfo PEM `public_key_pem`.
///
/// # Errors
/// Returns [`WitnessCoreError::BadPublicKey`] if the PEM does not parse, or
/// [`WitnessCoreError::SignatureInvalid`] if the DER is malformed or the
/// signature does not match.
pub fn verify_pem(
    public_key_pem: &str,
    payload: &[u8],
    signature_der: &[u8],
) -> Result<(), WitnessCoreError> {
    let verifying = parse_public_key_pem(public_key_pem)?;
    let signature =
        Signature::from_der(signature_der).map_err(|_| WitnessCoreError::SignatureInvalid)?;
    verifying
        .verify(payload, &signature)
        .map_err(|_| WitnessCoreError::SignatureInvalid)
}

/// Parse a SubjectPublicKeyInfo PEM-encoded ECDSA P-256 public key.
///
/// # Errors
/// Returns [`WitnessCoreError::BadPublicKey`] when the PEM cannot be decoded
/// or is not a P-256 key.
pub fn parse_public_key_pem(public_key_pem: &str) -> Result<VerifyingKey, WitnessCoreError> {
    let public = PublicKey::from_public_key_pem(public_key_pem).map_err(|source| {
        WitnessCoreError::BadPublicKey {
            detail: source.to_string(),
        }
    })?;
    Ok(VerifyingKey::from(public))
}

/// Encode a [`VerifyingKey`] as SubjectPublicKeyInfo PEM (LF line endings).
///
/// # Errors
/// Returns [`WitnessCoreError::PublicKeyEncode`] if encoding fails.
pub fn encode_public_key_pem(verifying: &VerifyingKey) -> Result<String, WitnessCoreError> {
    let public = PublicKey::from(verifying);
    public
        .to_public_key_pem(LineEnding::LF)
        .map_err(|source| WitnessCoreError::PublicKeyEncode {
            detail: source.to_string(),
        })
}

/// Compute the canonical P-256 key ID: lowercase hex SHA-256 of the 65-byte
/// SEC1 uncompressed-point encoding (`0x04 || X || Y`).
///
/// The encoding is independent of any DER/PEM wrapping, which keeps the
/// key_id stable across hardware-backed providers that may export their
/// public key in slightly different envelopes.
pub fn key_id(verifying: &VerifyingKey) -> String {
    let public = PublicKey::from(verifying);
    let encoded = public.to_encoded_point(false);
    let mut hasher = Sha256::new();
    hasher.update(encoded.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_sign_and_verify() {
        let key = generate_signing_key();
        let pem = encode_public_key_pem(key.verifying_key()).unwrap();
        let payload = b"the quick brown fox jumps over the lazy dog";
        let signature = sign(&key, payload);
        verify_pem(&pem, payload, &signature).expect("freshly signed payload must verify");
    }

    #[test]
    fn rejects_signature_for_different_payload() {
        let key = generate_signing_key();
        let pem = encode_public_key_pem(key.verifying_key()).unwrap();
        let signature = sign(&key, b"original payload");
        let err = verify_pem(&pem, b"different payload", &signature)
            .expect_err("signature must fail against a different payload");
        assert!(matches!(err, WitnessCoreError::SignatureInvalid));
    }

    #[test]
    fn rejects_signature_under_different_key() {
        let key_a = generate_signing_key();
        let key_b = generate_signing_key();
        let pem_b = encode_public_key_pem(key_b.verifying_key()).unwrap();
        let signature = sign(&key_a, b"hello");
        let err = verify_pem(&pem_b, b"hello", &signature)
            .expect_err("signature must fail under an unrelated key");
        assert!(matches!(err, WitnessCoreError::SignatureInvalid));
    }

    #[test]
    fn rejects_malformed_der_signature() {
        let key = generate_signing_key();
        let pem = encode_public_key_pem(key.verifying_key()).unwrap();
        let err = verify_pem(&pem, b"hello", &[0x00, 0x01, 0x02])
            .expect_err("garbage DER must fail to parse");
        assert!(matches!(err, WitnessCoreError::SignatureInvalid));
    }

    #[test]
    fn key_id_is_stable_across_pem_round_trip() {
        let key = generate_signing_key();
        let direct = key_id(key.verifying_key());
        let pem = encode_public_key_pem(key.verifying_key()).unwrap();
        let parsed = parse_public_key_pem(&pem).unwrap();
        let through_pem = key_id(&parsed);
        assert_eq!(
            direct, through_pem,
            "the SHA-256 of the SEC1 uncompressed point must be invariant under SPKI PEM round-trip"
        );
    }

    #[test]
    fn key_id_distinguishes_distinct_keys() {
        let a = generate_signing_key();
        let b = generate_signing_key();
        assert_ne!(
            key_id(a.verifying_key()),
            key_id(b.verifying_key()),
            "two freshly generated keys must produce distinct key_id values"
        );
    }

    #[test]
    fn parse_public_key_pem_rejects_garbage() {
        let err =
            parse_public_key_pem("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")
                .expect_err("PEM with non-P-256 content must fail to parse");
        assert!(matches!(err, WitnessCoreError::BadPublicKey { .. }));
    }
}
