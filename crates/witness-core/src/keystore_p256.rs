//! OS-keychain backed ECDSA P-256 key storage.
//!
//! Parallel to [`crate::keystore`] but stores a 32-byte P-256 private scalar
//! instead of an Ed25519 seed. The two storage entries are independent: a
//! capture host may carry both, and the seal path picks based on the
//! configured key provider.
//!
//! Storage: the 32-byte scalar is base64-encoded and stored in the OS
//! keychain under service [`KEYRING_SERVICE`] and account
//! [`KEYRING_ACCOUNT`]. Both differ from the Ed25519 entry's coordinates so
//! key material does not collide.

use base64::Engine;
use keyring::Entry;
use p256::ecdsa::SigningKey;
use zeroize::Zeroizing;

use crate::error::WitnessCoreError;
use crate::signing_ecdsa::generate_signing_key;

/// Service name used in the OS keychain for the P-256 device key. Distinct
/// from the Ed25519 entry so the two can coexist on the same host.
pub const KEYRING_SERVICE: &str = "tech.aftermath.gemma-witness";
/// Account name used in the OS keychain for the P-256 device key.
pub const KEYRING_ACCOUNT: &str = "device-signing-key-ecdsa-p256-v1";

/// Test-only: delete the P-256 device key from the keychain. Public so
/// developer-rotation workflows can call it.
///
/// # Errors
/// Returns [`WitnessCoreError::Keyring`] for keychain failures other than
/// "not found".
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

/// Generate a key on first call, or load the existing one on subsequent
/// calls. The private scalar is stored in the OS keychain and zeroized on
/// drop. Only [`SigningKey`] handles cross the public API.
///
/// # Errors
/// Returns [`WitnessCoreError::Keyring`] if the keychain cannot be reached.
pub(crate) fn load_or_create_signing_key() -> Result<SigningKey, WitnessCoreError> {
    match read_scalar_b64()? {
        Some(scalar_b64) => decode_scalar(&scalar_b64),
        None => {
            let key = generate_signing_key();
            let scalar_bytes = Zeroizing::new(key.to_bytes());
            let scalar_b64 =
                Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(*scalar_bytes));
            write_scalar_b64(&scalar_b64)?;
            Ok(key)
        }
    }
}

fn decode_scalar(scalar_b64: &Zeroizing<String>) -> Result<SigningKey, WitnessCoreError> {
    let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(scalar_b64.as_bytes())
            .map_err(|source| WitnessCoreError::Keyring {
                detail: format!("stored P-256 scalar was not valid base64: {source}"),
            })?,
    );
    if bytes.len() != 32 {
        return Err(WitnessCoreError::Keyring {
            detail: format!(
                "stored P-256 scalar was {} bytes, expected 32. \
                 the keychain entry may have been written by an incompatible build.",
                bytes.len()
            ),
        });
    }
    SigningKey::from_slice(&bytes).map_err(|source| WitnessCoreError::Keyring {
        detail: format!(
            "stored P-256 scalar did not decode into a valid signing key: {source}. \
             the keychain entry may be corrupted; clear it with delete_device_key."
        ),
    })
}

fn read_scalar_b64() -> Result<Option<Zeroizing<String>>, WitnessCoreError> {
    let entry = open_entry()?;
    match entry.get_password() {
        Ok(value) => Ok(Some(Zeroizing::new(value))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(err) => Err(WitnessCoreError::Keyring {
            detail: format!("get_password failed for P-256 entry: {err}"),
        }),
    }
}

fn write_scalar_b64(scalar_b64: &str) -> Result<(), WitnessCoreError> {
    let entry = open_entry()?;
    entry
        .set_password(scalar_b64)
        .map_err(|err| WitnessCoreError::Keyring {
            detail: format!("set_password failed for P-256 entry: {err}"),
        })
}

fn open_entry() -> Result<Entry, WitnessCoreError> {
    Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT).map_err(|err| WitnessCoreError::Keyring {
        detail: format!("could not open keyring entry {KEYRING_SERVICE}/{KEYRING_ACCOUNT}: {err}"),
    })
}
