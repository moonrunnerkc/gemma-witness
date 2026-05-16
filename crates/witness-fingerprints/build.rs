//! Generates a static EMBEDDED_ENTRIES table from `inference/fingerprints/`
//! and enforces the registry envelope's content gate at compile time.
//!
//! Each entry in `index.json` is turned into one row of the form
//! `(model_id, revision, include_str!(file))`. The table is written to
//! $OUT_DIR/embedded_entries.rs and pulled into the crate with `include!`.
//!
//! Before any embedding happens, `registry-manifest.json` is loaded and
//! cross-checked against the on-disk file set: every file the envelope
//! claims to cover must hash to the SHA-256 it records, and no extra
//! file may appear in the directory. A mismatch fails the build. A
//! placeholder envelope (no signature yet) emits a `cargo:warning=` but
//! does not block the build, so workspaces can iterate before the first
//! signing run. The signature gate proper runs in CI via
//! `tools/sign-fingerprints verify --require-signed` and at verifier
//! load time.
//!
//! Running tools/seed-fingerprints adds an entry to index.json and writes
//! the matching per-model JSON; the maintainer then runs
//! `cargo run -p sign-fingerprints -- recompute` to refresh the envelope
//! and the next `cargo build` regenerates this table.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");
    let registry_dir = Path::new(&manifest_dir).join("../../inference/fingerprints");
    let index_path = registry_dir.join("index.json");

    println!("cargo:rerun-if-changed={}", index_path.display());

    enforce_registry_envelope(&registry_dir);

    let raw = fs::read_to_string(&index_path)
        .unwrap_or_else(|err| panic!("could not read {}: {err}", index_path.display()));
    let parsed: serde_json::Value =
        serde_json::from_str(&raw).expect("inference/fingerprints/index.json must be valid JSON");
    let entries = parsed
        .get("entries")
        .and_then(|v| v.as_array())
        .expect("index.json missing entries[]");

    if entries.is_empty() {
        panic!(
            "{} declares an empty entries[]. the fingerprint registry must list at least one (model_id, revision) entry; a shipping binary with no pinned fingerprints would fail every model_fingerprint check at verification time. add an entry via tools/seed-fingerprints before building.",
            index_path.display()
        );
    }

    let mut out = String::new();
    out.push_str("&[\n");
    for entry in entries {
        let model_id = entry
            .get("model_id")
            .and_then(|v| v.as_str())
            .expect("index entry missing model_id");
        let revision = entry
            .get("revision")
            .and_then(|v| v.as_str())
            .expect("index entry missing revision");
        let file = entry
            .get("file")
            .and_then(|v| v.as_str())
            .expect("index entry missing file");

        let abs_path = registry_dir.join(file);
        let abs_path = abs_path
            .canonicalize()
            .unwrap_or_else(|err| panic!("could not canonicalize {}: {err}", abs_path.display()));

        println!("cargo:rerun-if-changed={}", abs_path.display());

        out.push_str(&format!(
            "    ({:?}, {:?}, include_str!({:?})),\n",
            model_id,
            revision,
            abs_path.to_string_lossy()
        ));
    }
    out.push_str("]\n");

    let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR set by cargo");
    let dest = PathBuf::from(out_dir).join("embedded_entries.rs");
    fs::write(&dest, out).expect("write embedded_entries.rs");
}

/// Run the registry envelope's content gate. A hash mismatch, missing
/// file, or extra file fails the build. A placeholder envelope warns
/// loudly but does not block; the signature gate is enforced at the CI
/// boundary and at verifier load time so placeholder builds can never
/// reach end users.
fn enforce_registry_envelope(registry_dir: &Path) {
    let envelope_path = registry_dir.join(witness_fingerprint_verify::REGISTRY_MANIFEST_FILENAME);
    println!("cargo:rerun-if-changed={}", envelope_path.display());
    let bundle_path = registry_dir.join(witness_fingerprint_verify::REGISTRY_BUNDLE_FILENAME);
    println!("cargo:rerun-if-changed={}", bundle_path.display());

    let manifest = witness_fingerprint_verify::load_manifest(registry_dir).unwrap_or_else(|err| {
        panic!(
            "{} did not load: {err}. \
             run `cargo run -p sign-fingerprints -- recompute` to regenerate the envelope.",
            envelope_path.display()
        )
    });
    witness_fingerprint_verify::verify_consistency(registry_dir, &manifest).unwrap_or_else(|err| {
        panic!(
            "registry envelope content gate failed: {err}. \
             either run `cargo run -p sign-fingerprints -- recompute` to refresh \
             the envelope after a legitimate edit, or investigate why the registry diverged from {}.",
            envelope_path.display()
        )
    });
    if manifest.placeholder {
        println!(
            "cargo:warning=inference/fingerprints/registry-manifest.json is a placeholder. \
             the Sigstore signature gate is not in effect on this build. \
             release builds must run sign-fingerprints.yml first."
        );
    }
}
