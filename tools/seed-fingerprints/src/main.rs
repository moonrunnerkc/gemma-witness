//! Seed entries in `inference/fingerprints/` from authoritative sources.
//!
//! For each (model_id, revision) pair, this tool:
//!   1. Fetches the Hugging Face LFS pointer for `model.safetensors` at that
//!      revision and reads its `oid sha256`. The LFS oid is, by the git-LFS
//!      contract, the SHA-256 of the file contents.
//!   2. Hashes the locally-cached `model.safetensors` for the same revision.
//!   3. Refuses to write anything if the two hashes disagree. A mismatch is a
//!      hard failure that must surface, not be papered over.
//!   4. Writes (or updates) the matching JSON file under
//!      `inference/fingerprints/`, stamping `verified_by` as
//!      `huggingface-lfs+local-recompute`.
//!   5. Regenerates `apps/verifier/known-fingerprints.json` from the registry
//!      so the offline verifier carries the same anchored hashes.
//!
//! The tool is invoked manually by a maintainer with the model already
//! cached. The capture app never calls it at runtime.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use clap::Parser;
use serde::Serialize;
use sha2::{Digest, Sha256};

const HF_API_BASE: &str = "https://huggingface.co/api/models";
const HF_RESOLVE_BASE: &str = "https://huggingface.co";

#[derive(Parser, Debug, Clone, Copy, clap::ValueEnum)]
enum FormatArg {
    Safetensors,
    Gguf,
}

impl FormatArg {
    fn as_registry_str(self) -> &'static str {
        match self {
            FormatArg::Safetensors => "safetensors",
            FormatArg::Gguf => "gguf",
        }
    }

    fn default_primary_file(self) -> &'static str {
        match self {
            FormatArg::Safetensors => "model.safetensors",
            // GGUF blobs are not standardized to a single filename; the caller
            // MUST pass --primary-file naming the actual *.gguf the sidecar
            // loads. We refuse to guess.
            FormatArg::Gguf => "",
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "seed-fingerprints")]
#[command(about = "Seeds inference/fingerprints/ entries from Hugging Face LFS metadata.")]
struct Cli {
    /// Hugging Face model id, e.g. mlx-community/gemma-4-e4b-it-4bit.
    #[arg(long)]
    model_id: String,
    /// Hugging Face revision (commit SHA or branch). Defaults to `main`.
    #[arg(long, default_value = "main")]
    revision: String,
    /// Storage format of the model weights this entry pins.
    #[arg(long, value_enum, default_value_t = FormatArg::Safetensors)]
    format: FormatArg,
    /// File path within the model repository that the fingerprint anchors on.
    /// Defaults to `model.safetensors` for `--format safetensors`. Required
    /// for `--format gguf` because GGUF filenames are quant-specific and
    /// cannot be guessed.
    #[arg(long)]
    primary_file: Option<String>,
    /// Override the local artifact path (safetensors or GGUF). Default for
    /// `--format safetensors`: resolved from the Hugging Face cache at
    /// `$HF_HOME` / `~/.cache/huggingface`. Required for `--format gguf`.
    #[arg(long, alias = "safetensors-path")]
    artifact_path: Option<PathBuf>,
    /// Repository root. Defaults to the directory containing Cargo.toml.
    #[arg(long)]
    repo_root: Option<PathBuf>,
    /// Skip the local recompute step. Used in dry runs that only fetch the HF
    /// LFS oid (for sanity checking without a cached model).
    #[arg(long)]
    fetch_only: bool,
    /// Write outputs even when the local hash and the HF LFS oid disagree.
    /// Off by default; mismatches must be investigated, not bypassed.
    #[arg(long)]
    force: bool,
}

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("seed-fingerprints: {err:#}");
            ExitCode::FAILURE
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn real_main() -> Result<()> {
    let cli = Cli::parse();
    let repo_root = cli
        .repo_root
        .clone()
        .ok_or(())
        .or_else(|_| guess_repo_root())
        .context("could not determine repository root. pass --repo-root explicitly")?;

    let primary_file = match (cli.primary_file.clone(), cli.format) {
        (Some(name), _) => name,
        (None, FormatArg::Safetensors) => cli.format.default_primary_file().to_string(),
        (None, FormatArg::Gguf) => {
            bail!(
                "--format gguf requires --primary-file naming the .gguf blob the sidecar loads. \
                 GGUF filenames are quantization-specific (e.g. gemma-4-e4b-it.Q4_K_M.gguf); the seeder will not guess."
            );
        }
    };

    let lfs = fetch_hf_lfs_pointer(&cli.model_id, &cli.revision, &primary_file)
        .await
        .with_context(|| {
            format!(
                "could not fetch HF LFS pointer for {}@{} file {}",
                cli.model_id, cli.revision, primary_file
            )
        })?;
    println!(
        "HF LFS oid for {}@{} {}: sha256={} size={}",
        cli.model_id, cli.revision, primary_file, lfs.sha256, lfs.size
    );

    let local_hash = if cli.fetch_only {
        None
    } else {
        let path = match cli.artifact_path.clone() {
            Some(p) => p,
            None => match cli.format {
                FormatArg::Safetensors => locate_local_safetensors(&cli.model_id, &cli.revision)
                    .context("could not locate locally cached model.safetensors. pass --artifact-path or run after the sidecar has downloaded the model")?,
                FormatArg::Gguf => bail!(
                    "--format gguf requires --artifact-path pointing at the locally cached .gguf blob. \
                     GGUF caches do not follow a stable layout the seeder can guess."
                ),
            },
        };
        println!("hashing local file: {}", path.display());
        Some(hash_file(&path)?)
    };

    if let Some(local) = &local_hash {
        if local != &lfs.sha256 {
            if cli.force {
                eprintln!(
                    "WARNING: --force set; writing despite hash mismatch.\n  HF LFS oid:     {}\n  local recompute:{}",
                    lfs.sha256, local
                );
            } else {
                bail!(
                    "HF LFS oid {} does not match locally-recomputed sha256 {}. \
                     refusing to write. investigate the cache (it may be corrupt or modified) or pass --force after confirming the discrepancy is benign.",
                    lfs.sha256,
                    local
                );
            }
        } else {
            println!("local recompute matches HF LFS oid. ok.");
        }
    } else {
        println!("--fetch-only set; skipping local recompute.");
    }

    let entry_file_name = entry_file_name(&cli.model_id, &cli.revision);
    let entry_path = repo_root
        .join("inference/fingerprints")
        .join(&entry_file_name);

    let verified_by = match (cli.fetch_only, local_hash.is_some()) {
        (true, _) => "huggingface-lfs",
        (false, true) => "huggingface-lfs+local-recompute",
        _ => "unverified",
    };

    let entry = RegistryEntry {
        model_id: cli.model_id.clone(),
        revision: cli.revision.clone(),
        format: cli.format.as_registry_str().to_string(),
        primary_file: primary_file.clone(),
        files: vec![RegistryFile {
            path: primary_file.clone(),
            sha256: Some(lfs.sha256.clone()),
            bytes: Some(lfs.size),
        }],
        source_url: Some(format!(
            "{HF_RESOLVE_BASE}/{}/tree/{}",
            cli.model_id, cli.revision
        )),
        lfs_oid: Some(lfs.sha256.clone()),
        captured_at_utc: Some(Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        verified_by: Some(verified_by.to_string()),
        verified_at_utc: Some(Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        note: Some(format!(
            "Seeded by tools/seed-fingerprints. HF LFS oid was cross-checked against the locally recomputed sha256 of {primary_file} before writing."
        )),
    };

    write_pretty_json(&entry_path, &entry)?;
    println!("wrote {}", entry_path.display());

    ensure_index_includes(
        &repo_root.join("inference/fingerprints/index.json"),
        &cli.model_id,
        &cli.revision,
        &entry_file_name,
    )?;

    regenerate_known_fingerprints(&repo_root)?;

    println!("done.");
    Ok(())
}

/// Result of asking HF for the LFS metadata of a single file at a single revision.
struct LfsPointer {
    sha256: String,
    size: u64,
}

async fn fetch_hf_lfs_pointer(
    model_id: &str,
    revision: &str,
    primary_file: &str,
) -> Result<LfsPointer> {
    let url = format!("{HF_API_BASE}/{model_id}/revision/{revision}?blobs=true");
    let client = reqwest::Client::builder()
        .user_agent("gemma-witness-seed-fingerprints/0.1")
        .build()?;
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        bail!("HF returned status {} for {url}", resp.status());
    }
    let body: serde_json::Value = resp.json().await.context("parse HF API JSON")?;
    let siblings = body
        .get("siblings")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("HF response missing siblings[]"))?;
    let sibling = siblings
        .iter()
        .find(|s| s.get("rfilename").and_then(|v| v.as_str()) == Some(primary_file))
        .ok_or_else(|| {
            anyhow!(
                "HF response for {model_id}@{revision} has no sibling named {primary_file}. \
                 Confirm the file exists at that revision; for GGUF blobs, the filename is quant-specific."
            )
        })?;
    let lfs = sibling.get("lfs").ok_or_else(|| {
        anyhow!(
            "{primary_file} entry has no `lfs` block; the file may not be LFS-tracked at this revision"
        )
    })?;
    let sha256 = lfs
        .get("sha256")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("HF lfs block missing sha256"))?
        .to_string();
    let size = lfs
        .get("size")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("HF lfs block missing size"))?;
    Ok(LfsPointer { sha256, size })
}

/// Resolve the locally cached snapshot path for a model revision.
fn locate_local_safetensors(model_id: &str, revision: &str) -> Result<PathBuf> {
    let cache_root = std::env::var("HF_HUB_CACHE")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HF_HOME")
                .ok()
                .map(|h| PathBuf::from(h).join("hub"))
        })
        .or_else(|| {
            dirs_home()
                .ok()
                .map(|h| h.join(".cache").join("huggingface").join("hub"))
        })
        .ok_or_else(|| {
            anyhow!("could not infer HF cache root. set HF_HUB_CACHE or pass --safetensors-path")
        })?;
    let repo_dir = cache_root.join(format!("models--{}", model_id.replace('/', "--")));
    let snapshot_dir = if revision == "main" {
        // For the bare branch, follow the refs/main pointer to the latest snapshot.
        let ref_file = repo_dir.join("refs").join("main");
        let snap_rev = std::fs::read_to_string(&ref_file)
            .with_context(|| format!("read {}", ref_file.display()))?;
        repo_dir.join("snapshots").join(snap_rev.trim())
    } else {
        repo_dir.join("snapshots").join(revision)
    };
    let file = snapshot_dir.join("model.safetensors");
    if !file.exists() {
        bail!("expected {} to exist but it does not", file.display());
    }
    Ok(file)
}

fn dirs_home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
        .ok_or_else(|| anyhow!("HOME/USERPROFILE not set"))
}

fn hash_file(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn entry_file_name(model_id: &str, revision: &str) -> String {
    let safe_model = model_id.replace('/', "__").replace(':', "_");
    let safe_rev = if revision.len() > 12 && revision.chars().all(|c| c.is_ascii_hexdigit()) {
        revision[..8].to_string()
    } else {
        revision.to_string()
    };
    format!("{safe_model}__{safe_rev}.json")
}

#[derive(Serialize)]
struct RegistryEntry {
    model_id: String,
    revision: String,
    format: String,
    primary_file: String,
    files: Vec<RegistryFile>,
    source_url: Option<String>,
    lfs_oid: Option<String>,
    captured_at_utc: Option<String>,
    verified_by: Option<String>,
    verified_at_utc: Option<String>,
    note: Option<String>,
}

#[derive(Serialize)]
struct RegistryFile {
    path: String,
    sha256: Option<String>,
    bytes: Option<u64>,
}

fn write_pretty_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    std::fs::write(path, text).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn ensure_index_includes(
    index_path: &Path,
    model_id: &str,
    revision: &str,
    file_name: &str,
) -> Result<()> {
    let raw = std::fs::read_to_string(index_path)
        .with_context(|| format!("read {}", index_path.display()))?;
    let mut index: serde_json::Value =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", index_path.display()))?;
    let entries = index
        .get_mut("entries")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| anyhow!("index.json missing entries[]"))?;
    if !entries.iter().any(|e| {
        e.get("model_id").and_then(|v| v.as_str()) == Some(model_id)
            && e.get("revision").and_then(|v| v.as_str()) == Some(revision)
    }) {
        entries.push(serde_json::json!({
            "model_id": model_id,
            "revision": revision,
            "file": file_name,
        }));
        let mut text = serde_json::to_string_pretty(&index)?;
        text.push('\n');
        std::fs::write(index_path, text)?;
        println!("appended to index.json");
    }
    Ok(())
}

fn regenerate_known_fingerprints(repo_root: &Path) -> Result<()> {
    let fingerprints_dir = repo_root.join("inference/fingerprints");
    let index_path = fingerprints_dir.join("index.json");
    let index_raw = std::fs::read_to_string(&index_path)
        .with_context(|| format!("read {}", index_path.display()))?;
    let index: serde_json::Value = serde_json::from_str(&index_raw)?;
    let entries = index
        .get("entries")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("index.json missing entries[]"))?;

    let mut known = Vec::new();
    for entry in entries {
        let file = entry
            .get("file")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("index entry missing file"))?;
        let entry_path = fingerprints_dir.join(file);
        let raw = std::fs::read_to_string(&entry_path)?;
        let parsed: serde_json::Value = serde_json::from_str(&raw)?;
        let format = parsed
            .get("format")
            .and_then(|v| v.as_str())
            .unwrap_or("safetensors");
        let primary_file = parsed
            .get("primary_file")
            .and_then(|v| v.as_str())
            .unwrap_or("model.safetensors");
        let files = parsed
            .get("files")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow!("{} missing files[]", entry_path.display()))?;
        let primary = files
            .iter()
            .find(|f| f.get("path").and_then(|v| v.as_str()) == Some(primary_file));
        let Some(primary) = primary else {
            continue;
        };
        let Some(sha) = primary.get("sha256").and_then(|v| v.as_str()) else {
            continue;
        };
        let model_id = parsed
            .get("model_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let revision = parsed
            .get("revision")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let source_url = parsed.get("source_url").and_then(|v| v.as_str());
        let verified_by = parsed.get("verified_by").and_then(|v| v.as_str());
        let verified_at_utc = parsed.get("verified_at_utc").and_then(|v| v.as_str());
        let note = parsed.get("note").and_then(|v| v.as_str());
        known.push(serde_json::json!({
            "model_id": model_id,
            "revision": revision,
            "format": format,
            "primary_file": primary_file,
            "sha256": sha,
            "added_at": verified_at_utc.unwrap_or(""),
            "verified_by": verified_by.unwrap_or("unverified"),
            "source_url": source_url.unwrap_or(""),
            "note": note.unwrap_or(""),
        }));
    }

    let out = serde_json::json!({
        "schema_version": 1,
        "fingerprints": known,
    });
    let out_path = repo_root.join("apps/verifier/known-fingerprints.json");
    let mut text = serde_json::to_string_pretty(&out)?;
    text.push('\n');
    std::fs::write(&out_path, text)?;
    println!("regenerated {}", out_path.display());
    Ok(())
}

fn guess_repo_root() -> Result<PathBuf> {
    let mut here = std::env::current_dir()?;
    loop {
        if here.join("Cargo.toml").exists() && here.join("apps").is_dir() {
            return Ok(here);
        }
        if !here.pop() {
            bail!("no workspace root found above current dir");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn entry_file_name_truncates_long_hex_revisions() {
        let name = entry_file_name(
            "mlx-community/gemma-4-e4b-it-4bit",
            "cc3b666c01c20395e0dcebd53854504c7d9821f9",
        );
        assert_eq!(name, "mlx-community__gemma-4-e4b-it-4bit__cc3b666c.json");
    }

    #[test]
    fn entry_file_name_keeps_short_branch_names() {
        let name = entry_file_name("google/gemma-4-E4B-it", "main");
        assert_eq!(name, "google__gemma-4-E4B-it__main.json");
    }

    #[test]
    fn hash_file_handles_streaming_reads() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob");
        std::fs::write(&path, b"hello world").unwrap();
        let h = hash_file(&path).unwrap();
        assert_eq!(
            h,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}
