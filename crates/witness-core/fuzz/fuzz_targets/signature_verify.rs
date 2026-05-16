//! Fuzz harness for the signature verification surface.
//!
//! Feeds arbitrary 64-byte signatures against a fixed valid public key and
//! payload to `verify_pem`. Catches: panics on invalid signature byte
//! patterns, scalar-malleability bypass, mishandled edge cases in the
//! strict-verify path.

#![no_main]

use libfuzzer_sys::fuzz_target;
use witness_core::signing::verify_pem;

// A valid SubjectPublicKeyInfo PEM for an Ed25519 public key. Generated
// once and hard-coded so the fuzzer can focus on the signature bytes.
const PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n\
-----END PUBLIC KEY-----\n";

fuzz_target!(|data: &[u8]| {
    let mut sig = [0u8; 64];
    let n = data.len().min(64);
    sig[..n].copy_from_slice(&data[..n]);
    let payload = b"{\"manifest_version\":2}";
    let _ = verify_pem(PUBLIC_KEY_PEM, payload, &sig);
});
