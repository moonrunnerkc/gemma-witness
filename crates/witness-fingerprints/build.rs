//! Generates a static EMBEDDED_ENTRIES table from `inference/fingerprints/`.
//!
//! Each entry in `index.json` is turned into one row of the form
//! `(model_id, revision, include_str!(file))`. The table is written to
//! $OUT_DIR/embedded_entries.rs and pulled into the crate with `include!`.
//!
//! Running tools/seed-fingerprints adds an entry to index.json and writes the
//! matching per-model JSON; the next `cargo build` regenerates this table.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");
    let registry_dir = Path::new(&manifest_dir).join("../../inference/fingerprints");
    let index_path = registry_dir.join("index.json");

    println!("cargo:rerun-if-changed={}", index_path.display());

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
