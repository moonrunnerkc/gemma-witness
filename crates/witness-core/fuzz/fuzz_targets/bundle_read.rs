//! Fuzz harness for the bundle ZIP reader.
//!
//! Writes arbitrary bytes to a temp file then feeds the path to
//! `read_bundle`. The reader enforces per-entry and total-decompressed
//! size caps, rejects path traversal, and refuses unexpected entries; the
//! assertion is that no panic escapes the gauntlet on adversarial input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Write as _;
use witness_core::bundle_zip::read_bundle;

fuzz_target!(|data: &[u8]| {
    if data.len() > 4 << 20 {
        return;
    }
    let Ok(mut tmp) = tempfile::NamedTempFile::new() else {
        return;
    };
    if tmp.write_all(data).is_err() {
        return;
    }
    let _ = read_bundle(tmp.path());
});
