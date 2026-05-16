//! Fuzz harness for the JCS canonicalizer.
//!
//! Feeds arbitrary bytes to `serde_json::from_slice` and then runs
//! `witness_core::canonical::canonicalize` on any value that parses.
//! Asserts: no panics, output strictly smaller than 4 MiB for inputs under
//! 1 MiB (a coarse sanity bound that catches runaway-output bugs).

#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use witness_core::canonical::canonicalize;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1 << 20 {
        return;
    }
    let Ok(parsed): Result<Value, _> = serde_json::from_slice(data) else {
        return;
    };
    let Ok(bytes) = canonicalize(&parsed) else {
        return;
    };
    assert!(bytes.len() < 4 << 20, "canonical output unexpectedly large");
});
