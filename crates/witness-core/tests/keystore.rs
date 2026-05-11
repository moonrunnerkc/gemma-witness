//! Keystore integration: generate, sign, drop, fetch again, verify.
//!
//! These tests touch the live OS keychain. Each test uses a unique account
//! suffix to avoid colliding with the production credential and with other
//! parallel test runs.

use base64::Engine;
use ed25519_dalek::{Signature, SECRET_KEY_LENGTH};
use keyring::Entry;
use witness_core::keystore::{KEYRING_ACCOUNT, KEYRING_SERVICE};
use witness_core::signing::{generate_signing_key, parse_public_key_pem};

/// Helper: replicates `keystore::load_or_create_device_key` against a
/// scoped account so production credentials are untouched.
struct TestKeystore {
    account: String,
}

impl TestKeystore {
    fn new(suffix: &str) -> Self {
        Self {
            account: format!("{KEYRING_ACCOUNT}-test-{suffix}"),
        }
    }

    fn entry(&self) -> Entry {
        Entry::new(KEYRING_SERVICE, &self.account).expect("entry")
    }

    fn cleanup(&self) {
        let entry = self.entry();
        let _ = entry.delete_credential();
    }
}

fn read_seed(entry: &Entry) -> Option<String> {
    match entry.get_password() {
        Ok(v) => Some(v),
        Err(keyring::Error::NoEntry) => None,
        Err(err) => panic!("keychain unreachable: {err}"),
    }
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "keyring tests run on macOS in CI")]
fn keystore_persists_across_simulated_restart() {
    let store = TestKeystore::new("persist");
    store.cleanup();

    let entry = store.entry();
    assert!(read_seed(&entry).is_none(), "expected fresh slot");

    let key = generate_signing_key();
    let seed_b64 = base64::engine::general_purpose::STANDARD.encode(key.to_bytes());
    entry.set_password(&seed_b64).expect("set");
    let verifying_first = key.verifying_key();
    drop(key);

    let stored = read_seed(&entry).expect("seed present after store");
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(stored.as_bytes())
        .expect("b64");
    assert_eq!(bytes.len(), SECRET_KEY_LENGTH);
    let mut seed = [0u8; SECRET_KEY_LENGTH];
    seed.copy_from_slice(&bytes);
    let restored = ed25519_dalek::SigningKey::from_bytes(&seed);

    assert_eq!(
        verifying_first.as_bytes(),
        restored.verifying_key().as_bytes(),
        "public key must persist across simulated restart"
    );

    let payload = b"manifest canonical bytes";
    let sig: Signature = ed25519_dalek::Signer::sign(&restored, payload);
    restored
        .verifying_key()
        .verify_strict(payload, &sig)
        .expect("verify");

    store.cleanup();
}

#[test]
fn signing_key_pem_round_trips() {
    let key = generate_signing_key();
    let pem = witness_core::signing::encode_public_key_pem(&key.verifying_key()).unwrap();
    let parsed = parse_public_key_pem(&pem).unwrap();
    assert_eq!(parsed.as_bytes(), key.verifying_key().as_bytes());
}
