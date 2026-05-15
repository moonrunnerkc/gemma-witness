//! OS-keychain backed Ed25519 key storage.
//!
//! Private key bytes never leave this module. The public API accepts a
//! message and returns a signature; the [`SigningKey`] handle exists only
//! for the duration of a single `sign_with_device_key` call.
//!
//! Storage: the 32-byte seed is base64-encoded and stored in the OS
//! keychain under service `tech.aftermath.gemma-witness` and account
//! `device-signing-key-v1`.

use base64::Engine;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use keyring::Entry;
use zeroize::Zeroizing;

use crate::error::WitnessCoreError;
use crate::signing::{encode_public_key_pem, generate_signing_key, key_id, sign};

/// Service name used in the OS keychain.
pub const KEYRING_SERVICE: &str = "tech.aftermath.gemma-witness";
/// Account name used in the OS keychain.
pub const KEYRING_ACCOUNT: &str = "device-signing-key-v1";

/// Public-key surface returned by [`load_or_create_device_key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePublicKey {
    pub public_key_pem: String,
    pub key_id: String,
}

/// Generate a key on first call, or load the existing one on subsequent
/// calls. The private seed is stored in the OS keychain and dropped before
/// returning. Only the public-key surface is returned.
///
/// # Errors
/// Returns [`WitnessCoreError::Keyring`] if the keychain cannot be reached
/// or returns an error other than "not found".
pub fn load_or_create_device_key() -> Result<DevicePublicKey, WitnessCoreError> {
    let signing = load_or_create_signing_key()?;
    let verifying = signing.verifying_key();
    let public_key_pem = encode_public_key_pem(&verifying)?;
    let key_id = key_id(&verifying);
    drop(signing);
    Ok(DevicePublicKey {
        public_key_pem,
        key_id,
    })
}

/// Read the device public key without creating one if it is missing.
///
/// # Errors
/// Returns [`WitnessCoreError::NoDeviceKey`] when no key exists yet, or
/// [`WitnessCoreError::Keyring`] for keychain failures.
pub fn load_device_public_key() -> Result<DevicePublicKey, WitnessCoreError> {
    let signing = load_signing_key()?;
    let verifying = signing.verifying_key();
    let public_key_pem = encode_public_key_pem(&verifying)?;
    let key_id = key_id(&verifying);
    drop(signing);
    Ok(DevicePublicKey {
        public_key_pem,
        key_id,
    })
}

/// Sign `payload` with the device key. The key handle is loaded from the
/// keychain, used once, and dropped before return.
///
/// # Errors
/// Returns [`WitnessCoreError::NoDeviceKey`] if no key has been generated
/// yet, or [`WitnessCoreError::Keyring`] for any keychain failure.
pub fn sign_with_device_key(payload: &[u8]) -> Result<Signature, WitnessCoreError> {
    let signing = load_signing_key()?;
    let signature = sign(&signing, payload);
    drop(signing);
    Ok(signature)
}

/// Test-only: delete the device key from the keychain. Used to simulate a
/// fresh-install state between test runs. This function is also useful for
/// developer rotation, so it stays public.
pub fn delete_device_key() -> Result<(), WitnessCoreError> {
    let entry = open_entry()?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(err) => Err(WitnessCoreError::Keyring {
            detail: format!("delete_credential failed: {err}"),
        }),
    }
}

fn load_or_create_signing_key() -> Result<SigningKey, WitnessCoreError> {
    match read_seed_b64()? {
        Some(seed_b64) => decode_seed(&seed_b64),
        None => {
            let key = generate_signing_key();
            let seed_b64 =
                Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(key.to_bytes()));
            write_seed_b64(&seed_b64)?;
            Ok(key)
        }
    }
}

fn load_signing_key() -> Result<SigningKey, WitnessCoreError> {
    match read_seed_b64()? {
        Some(seed_b64) => decode_seed(&seed_b64),
        None => Err(WitnessCoreError::NoDeviceKey),
    }
}

fn decode_seed(seed_b64: &Zeroizing<String>) -> Result<SigningKey, WitnessCoreError> {
    let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(seed_b64.as_bytes())
            .map_err(|source| WitnessCoreError::Keyring {
                detail: format!("stored seed was not valid base64: {source}"),
            })?,
    );
    if bytes.len() != SECRET_KEY_LENGTH {
        return Err(WitnessCoreError::Keyring {
            detail: format!(
                "stored seed was {} bytes, expected {}",
                bytes.len(),
                SECRET_KEY_LENGTH
            ),
        });
    }
    let mut seed = Zeroizing::new([0u8; SECRET_KEY_LENGTH]);
    seed.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&seed))
}

fn read_seed_b64() -> Result<Option<Zeroizing<String>>, WitnessCoreError> {
    let entry = open_entry()?;
    match entry.get_password() {
        Ok(value) => Ok(Some(Zeroizing::new(value))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(err) => Err(WitnessCoreError::Keyring {
            detail: format!("get_password failed: {err}"),
        }),
    }
}

fn write_seed_b64(seed_b64: &str) -> Result<(), WitnessCoreError> {
    let entry = open_entry()?;
    entry
        .set_password(seed_b64)
        .map_err(|err| WitnessCoreError::Keyring {
            detail: format!("set_password failed: {err}"),
        })
}

fn open_entry() -> Result<Entry, WitnessCoreError> {
    Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT).map_err(|err| WitnessCoreError::Keyring {
        detail: format!("could not open keyring entry {KEYRING_SERVICE}/{KEYRING_ACCOUNT}: {err}"),
    })
}

/// Recompute the verifying key from the stored seed. Intended for tests
/// that need to confirm the public key persists across simulated restarts.
#[doc(hidden)]
pub fn debug_verifying_key() -> Result<VerifyingKey, WitnessCoreError> {
    let key = load_signing_key()?;
    let verifying = key.verifying_key();
    drop(key);
    Ok(verifying)
}
