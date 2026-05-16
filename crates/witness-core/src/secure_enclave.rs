//! macOS Secure Enclave [`KeyProvider`] backend.
//!
//! Generates an ECDSA P-256 key inside the Secure Enclave Processor (SEP)
//! such that the private key is never accessible to the host CPU and never
//! exposed through any Rust API. Signing requests are forwarded to the SEP,
//! which returns ASN.1/DER-encoded ECDSA signatures that match the wire
//! format produced by [`crate::signing_ecdsa`].
//!
//! This module is compiled only on macOS with `--features hardware-keys`.
//! Other targets fall through to a `compile_error!` in [`crate::key_provider`]
//! until their hardware backends land (TPM 2.0 on Linux, NCrypt on Windows).
//!
//! Persistence: the provider does not set `kSecAttrIsPermanent`, which causes
//! `security-framework` to default `kSecAttrIsPermanent=false`. That means the
//! key lives only for the lifetime of the [`SecureEnclaveProvider`] handle
//! and disappears when the process exits or the cache is cleared. Unsigned
//! development binaries cannot create persistent SEP keys without the
//! Keychain Access Group entitlement; a non-persistent key works on every
//! dev host. The capture-app shipping integration (WS3-7) will swap in a
//! persistent variant once the production binary carries the entitlement.
//!
//! Key shape:
//! - `KeyType::ec_sec_prime_random()` (kSecAttrKeyTypeECSECPrimeRandom)
//! - 256 bits (P-256 / secp256r1)
//! - `Token::SecureEnclave` (kSecAttrTokenIDSecureEnclave)
//!
//! Public-key handling:
//! - `SecKeyCopyPublicKey` extracts the SEP-resident public key.
//! - `SecKeyCopyExternalRepresentation` returns the 65-byte SEC1
//!   uncompressed-point form (`0x04 || X || Y`).
//! - We wrap it in the standard 91-byte SubjectPublicKeyInfo PEM via the
//!   `p256` crate so the wire form is byte-identical to what the software
//!   provider, the JS verifier's SPKI parser, and `openssl ec -pubout`
//!   produce. This keeps the verifier oblivious to where the key was born.
//!
//! Signing:
//! - `kSecKeyAlgorithmECDSASignatureMessageX962SHA256`: the SEP digests the
//!   payload with SHA-256 internally and emits DER, matching the encoding
//!   `p256::ecdsa::Signature::to_der` produces.

use std::sync::Mutex;

use p256::pkcs8::der::pem::LineEnding;
use p256::pkcs8::EncodePublicKey;
use p256::PublicKey;
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};

use crate::error::WitnessCoreError;
use crate::key_provider::{KeyProvider, PublicKeyHandle, SigningAlgorithm};
use crate::signing_ecdsa::key_id;

/// Hardware-backed [`KeyProvider`] that anchors the signing key in the
/// Apple Secure Enclave.
///
/// One instance owns at most one SEP key handle; calls are serialized
/// through an internal `Mutex` because `SecKey` is `Send + Sync` but the SEP
/// itself has a finite throughput and concurrent sign calls offer no win.
#[derive(Default)]
pub struct SecureEnclaveProvider {
    cached_key: Mutex<Option<SecKey>>,
}

impl std::fmt::Debug for SecureEnclaveProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureEnclaveProvider")
            .field("cached_key", &self.cached_key.lock().map(|g| g.is_some()))
            .finish()
    }
}

impl SecureEnclaveProvider {
    /// Construct a provider with no cached key. The first call to
    /// [`KeyProvider::load_or_create_public`] or [`KeyProvider::sign`]
    /// generates one inside the SEP.
    pub fn new() -> Self {
        Self::default()
    }

    fn with_key<T>(
        &self,
        f: impl FnOnce(&SecKey) -> Result<T, WitnessCoreError>,
    ) -> Result<T, WitnessCoreError> {
        let mut guard = self
            .cached_key
            .lock()
            .map_err(|err| WitnessCoreError::Keyring {
                detail: format!("Secure Enclave key cache lock poisoned: {err}"),
            })?;
        if guard.is_none() {
            *guard = Some(generate_sep_key()?);
        }
        let key = guard.as_ref().ok_or_else(|| WitnessCoreError::Keyring {
            detail: "Secure Enclave key cache was empty after generation".to_string(),
        })?;
        f(key)
    }
}

impl KeyProvider for SecureEnclaveProvider {
    fn load_or_create_public(&self) -> Result<PublicKeyHandle, WitnessCoreError> {
        self.with_key(|key| {
            let sec1 = sep_public_key_sec1(key)?;
            let public_key_pem = sec1_to_spki_pem(&sec1)?;
            let public = p256::PublicKey::from_sec1_bytes(&sec1).map_err(|source| {
                WitnessCoreError::BadPublicKey {
                    detail: format!(
                        "SEC1 point exported by the Secure Enclave did not parse as a P-256 \
                         public key: {source}. this indicates a Security.framework regression \
                         or a curve mismatch in the key-generation options."
                    ),
                }
            })?;
            Ok(PublicKeyHandle {
                algorithm: SigningAlgorithm::EcdsaP256,
                public_key_pem,
                key_id: key_id(&p256::ecdsa::VerifyingKey::from(public)),
            })
        })
    }

    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, WitnessCoreError> {
        self.with_key(|key| {
            key.create_signature(Algorithm::ECDSASignatureMessageX962SHA256, payload)
                .map_err(|err| WitnessCoreError::Keyring {
                    detail: format!(
                        "Secure Enclave signing failed: {err}. \
                         confirm the device has an SEP (Apple Silicon or T2) and \
                         that the binary has not been killed by Gatekeeper."
                    ),
                })
        })
    }

    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::EcdsaP256
    }
}

/// Ask the SEP to mint a fresh, non-persistent P-256 keypair.
fn generate_sep_key() -> Result<SecKey, WitnessCoreError> {
    let mut options = GenerateKeyOptions::default();
    options
        .set_key_type(KeyType::ec_sec_prime_random())
        .set_size_in_bits(256)
        .set_token(Token::SecureEnclave)
        .set_label("tech.aftermath.gemma-witness device signing key (SEP)");
    SecKey::new(&options).map_err(|err| WitnessCoreError::Keyring {
        detail: format!(
            "could not generate a Secure Enclave key: {err}. \
             this device may not have an SEP (only Apple Silicon and T2 Macs do), \
             or the keychain rejected the request. on unsigned dev builds, only \
             non-persistent SEP keys are permitted."
        ),
    })
}

/// Pull the 65-byte SEC1 uncompressed-point encoding of a SEP key's public
/// half (`0x04 || X || Y`).
fn sep_public_key_sec1(private_key: &SecKey) -> Result<Vec<u8>, WitnessCoreError> {
    let public = private_key
        .public_key()
        .ok_or_else(|| WitnessCoreError::Keyring {
            detail: "SecKeyCopyPublicKey returned NULL for a freshly-generated SEP key. \
                     this should not happen and points at a Security.framework regression."
                .to_string(),
        })?;
    let data = public
        .external_representation()
        .ok_or_else(|| WitnessCoreError::Keyring {
            detail: "SecKeyCopyExternalRepresentation returned NULL for a SEP public key. \
                     SEP private keys are correctly non-extractable, but the public half \
                     must always be exportable."
                .to_string(),
        })?;
    let bytes = data.bytes().to_vec();
    if bytes.len() != 65 || bytes.first() != Some(&0x04) {
        return Err(WitnessCoreError::Keyring {
            detail: format!(
                "SEP public key exported {} bytes starting with 0x{:02x}; expected 65 bytes \
                 starting with 0x04 (SEC1 uncompressed). only P-256 keys are supported.",
                bytes.len(),
                bytes.first().copied().unwrap_or(0)
            ),
        });
    }
    Ok(bytes)
}

/// Convert a 65-byte SEC1 uncompressed point into a 91-byte SPKI PEM, the
/// same shape `signing_ecdsa::encode_public_key_pem` produces for software
/// keys. The verifier consumes this directly.
fn sec1_to_spki_pem(sec1: &[u8]) -> Result<String, WitnessCoreError> {
    let public =
        PublicKey::from_sec1_bytes(sec1).map_err(|source| WitnessCoreError::BadPublicKey {
            detail: format!(
                "SEC1 point exported by the Secure Enclave did not parse as a P-256 public key: \
                 {source}."
            ),
        })?;
    public
        .to_public_key_pem(LineEnding::LF)
        .map_err(|source| WitnessCoreError::PublicKeyEncode {
            detail: format!(
                "could not PEM-encode the SEP public key as SPKI: {source}. \
                 this indicates a p256 crate regression, not a hardware fault."
            ),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity test that does not touch the SEP. Confirms the SEC1->SPKI
    /// adapter accepts a 65-byte uncompressed point and emits the same PEM
    /// shape the software provider produces, so the verifier path is shared.
    #[test]
    fn sec1_to_spki_pem_round_trips_a_software_key() {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let key = crate::signing_ecdsa::generate_signing_key();
        let public = PublicKey::from(key.verifying_key());
        let encoded = public.to_encoded_point(false);
        let sec1 = encoded.as_bytes().to_vec();
        assert_eq!(sec1.len(), 65, "P-256 uncompressed point is always 65 bytes");
        let pem = sec1_to_spki_pem(&sec1).expect("encode SPKI from valid SEC1 point");
        let parsed = crate::signing_ecdsa::parse_public_key_pem(&pem)
            .expect("our SPKI output must parse via the verifier path");
        assert_eq!(
            crate::signing_ecdsa::key_id(&parsed),
            crate::signing_ecdsa::key_id(key.verifying_key()),
            "SPKI re-encoding must preserve the SEC1 key_id"
        );
    }

    /// SEC1 length validation: reject any payload that is not 65 bytes
    /// starting with 0x04. Keeps malformed input from the SEP loud rather
    /// than silently producing a key the verifier would later reject.
    #[test]
    fn sec1_to_spki_pem_rejects_wrong_length() {
        let err = sec1_to_spki_pem(&[0x04; 64]).expect_err("64-byte input must fail");
        assert!(matches!(err, WitnessCoreError::BadPublicKey { .. }));
    }

    /// Live SEP round-trip. Gated on `WITNESS_RUN_SEP_TESTS=1` because it
    /// requires Apple Silicon (or a T2 Mac) and writes nothing the test
    /// runner does not want. The key is non-persistent and disappears when
    /// the provider drops at end of test.
    #[test]
    fn secure_enclave_provider_round_trips_when_run_on_real_hardware() {
        if std::env::var_os("WITNESS_RUN_SEP_TESTS").is_none() {
            eprintln!(
                "secure_enclave_provider_round_trips_when_run_on_real_hardware: skipping. \
                 set WITNESS_RUN_SEP_TESTS=1 to enable (requires Apple Silicon or T2)."
            );
            return;
        }

        let provider = SecureEnclaveProvider::new();
        let handle = provider
            .load_or_create_public()
            .expect("SEP key generation must succeed on Apple Silicon");
        assert_eq!(handle.algorithm, SigningAlgorithm::EcdsaP256);
        assert!(
            handle.public_key_pem.contains("BEGIN PUBLIC KEY"),
            "SEP public key must come out as PEM; got: {}",
            handle.public_key_pem
        );
        assert_eq!(handle.key_id.len(), 64, "SHA-256 hex is 64 chars");

        let payload = b"witness-core SEP round-trip payload";
        let signature = provider.sign(payload).expect("SEP must sign");
        crate::signing_ecdsa::verify_pem(&handle.public_key_pem, payload, &signature)
            .expect("software verifier must accept the SEP signature");

        // A second sign call must produce a verifying signature too, and
        // both signatures must come from the same key (key_id is stable).
        let again = provider.sign(payload).expect("SEP must sign again");
        crate::signing_ecdsa::verify_pem(&handle.public_key_pem, payload, &again)
            .expect("second SEP signature must also verify");
        let handle_again = provider
            .load_or_create_public()
            .expect("cached SEP public key must still load");
        assert_eq!(handle.key_id, handle_again.key_id);
    }
}
