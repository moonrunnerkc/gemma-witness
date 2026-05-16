//! Fuzz harness for manifest deserialization.
//!
//! Feeds arbitrary bytes to `serde_json::from_slice::<Manifest>`. The
//! manifest deserializer uses `deny_unknown_fields` and structural type
//! constraints; the assertion is that no panic escapes the type-driven
//! parser. Typed errors are expected and ignored.

#![no_main]

use libfuzzer_sys::fuzz_target;
use witness_core::Manifest;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1 << 20 {
        return;
    }
    let _ = serde_json::from_slice::<Manifest>(data);
});
