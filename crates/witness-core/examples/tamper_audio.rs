//! Tamper the audio entry of a sealed `.witness` bundle for tamper-detection demos.
//!
//! Reads the bundle, XORs byte 100 of `assets/audio.wav` with 0x42, and writes
//! the result through the deterministic bundle writer so the structural bytes
//! around the audio entry remain consistent. The bundle's signature is left
//! intact so the verifier failure is unambiguously at the asset-hash step.
//!
//! Usage: `cargo run -p witness-core --example tamper_audio -- <input> <output>`

use std::path::PathBuf;

use witness_core::bundle_builder::paths;
use witness_core::bundle_zip::{read_bundle, write_bundle, ZipEntry};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: tamper_audio <input.witness> <output.witness>");
        std::process::exit(2);
    }
    let input = PathBuf::from(&args[1]);
    let output = PathBuf::from(&args[2]);

    let mut entries = read_bundle(&input)?;
    let audio = entries.get_mut(paths::AUDIO).ok_or_else(|| {
        format!(
            "bundle {input:?} has no {} entry; not a tampering target",
            paths::AUDIO
        )
    })?;
    if audio.len() <= 100 {
        return Err(format!(
            "audio entry is only {} bytes; cannot flip byte 100",
            audio.len()
        )
        .into());
    }
    audio[100] ^= 0x42;

    let zipped: Vec<ZipEntry> = entries
        .into_iter()
        .map(|(path, data)| ZipEntry { path, data })
        .collect();
    write_bundle(&output, &zipped)?;
    println!("tampered bundle written: {output:?}");
    Ok(())
}
