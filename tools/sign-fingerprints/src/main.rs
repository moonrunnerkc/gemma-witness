//! CLI around `witness-fingerprint-verify`. Three subcommands gate the
//! lifecycle of `inference/fingerprints/registry-manifest.json`:
//!
//! - `recompute`  rebuilds the envelope from on-disk state. Always writes
//!                with `placeholder=true`; flipping the flag is the
//!                signing workflow's job.
//! - `verify`     content gate (and, if the envelope claims
//!                `placeholder=false`, signature gate too). Used by
//!                `crates/witness-fingerprints/build.rs` and by CI
//!                wherever the envelope's authenticity matters.
//! - `flip-placeholder`
//!                editorial-only step run by the signing workflow after
//!                `cosign sign-blob` produces `registry-manifest.sigstore`.
//!                Sets `placeholder=false`, fills `signed_at_utc`, drops
//!                `placeholder_reason`, and writes the envelope back.

use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use witness_fingerprint_verify::{
    REGISTRY_MANIFEST_FILENAME, RegistryManifest, canonical_bytes, compute_manifest, load_manifest,
    signature::verify_signature, verify_consistency,
};

#[derive(Parser)]
#[command(version, about = "Maintain and verify the fingerprint registry envelope.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Rebuild registry-manifest.json from the contents of
    /// inference/fingerprints/. Always writes with placeholder=true; the
    /// signing workflow flips the flag after cosign produces the bundle.
    Recompute {
        #[arg(
            long,
            default_value = "inference/fingerprints",
            help = "Path to the registry directory. Defaults to the in-tree location."
        )]
        registry_dir: PathBuf,
    },
    /// Run the content gate (hash check). When the envelope claims
    /// placeholder=false, also runs the Sigstore signature gate.
    /// Exit codes:
    ///   0 = all gates passed
    ///   1 = generic failure
    ///   2 = placeholder envelope with --require-signed
    ///   3 = signature gate failed
    ///   4 = content gate failed
    Verify {
        #[arg(long, default_value = "inference/fingerprints")]
        registry_dir: PathBuf,
        /// Refuse to exit 0 when the envelope is still a placeholder.
        /// CI must set this on the release tag path; pre-release builds
        /// leave it off so the registry boots before the first signing
        /// run.
        #[arg(long)]
        require_signed: bool,
    },
    /// Editorial step run by the signing workflow once cosign has
    /// produced registry-manifest.sigstore. Writes back an envelope with
    /// placeholder=false, fills signed_at_utc, and drops
    /// placeholder_reason.
    FlipPlaceholder {
        #[arg(long, default_value = "inference/fingerprints")]
        registry_dir: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Recompute { registry_dir } => run_recompute(&registry_dir),
        Command::Verify {
            registry_dir,
            require_signed,
        } => run_verify(&registry_dir, require_signed),
        Command::FlipPlaceholder { registry_dir } => run_flip_placeholder(&registry_dir),
    }
}

fn run_recompute(registry_dir: &std::path::Path) -> Result<()> {
    let manifest = compute_manifest(registry_dir)
        .with_context(|| format!("could not compute manifest from {}", registry_dir.display()))?;
    write_manifest(registry_dir, &manifest)?;
    eprintln!(
        "wrote {} with placeholder=true covering {} files",
        registry_dir.join(REGISTRY_MANIFEST_FILENAME).display(),
        manifest.covered_files.len()
    );
    Ok(())
}

fn run_verify(registry_dir: &std::path::Path, require_signed: bool) -> Result<()> {
    let manifest = load_manifest(registry_dir).with_context(|| {
        format!(
            "could not load {}",
            registry_dir.join(REGISTRY_MANIFEST_FILENAME).display()
        )
    })?;
    verify_consistency(registry_dir, &manifest).map_err(|e| anyhow!("content gate failed: {e}"))?;
    if manifest.placeholder {
        if require_signed {
            bail!(
                "envelope is a placeholder and --require-signed was passed. \
                 the signing workflow has not produced registry-manifest.sigstore yet"
            );
        }
        eprintln!(
            "WARNING: registry envelope is still a placeholder. \
             run .github/workflows/sign-fingerprints.yml to produce registry-manifest.sigstore"
        );
        return Ok(());
    }
    verify_signature(registry_dir, &manifest)
        .map_err(|e| anyhow!("signature gate failed: {e}"))?;
    eprintln!("content + signature gates passed");
    Ok(())
}

fn run_flip_placeholder(registry_dir: &std::path::Path) -> Result<()> {
    let mut manifest = load_manifest(registry_dir).with_context(|| {
        format!(
            "could not load {}",
            registry_dir.join(REGISTRY_MANIFEST_FILENAME).display()
        )
    })?;
    if !manifest.placeholder {
        eprintln!("envelope already has placeholder=false; no change");
        return Ok(());
    }
    verify_consistency(registry_dir, &manifest)
        .map_err(|e| anyhow!("refusing to flip placeholder: content gate failed: {e}"))?;
    let bundle_path = registry_dir.join(witness_fingerprint_verify::REGISTRY_BUNDLE_FILENAME);
    if !bundle_path.exists() {
        bail!(
            "refusing to flip placeholder: {} does not exist. \
             run cosign sign-blob first",
            bundle_path.display()
        );
    }
    manifest.placeholder = false;
    manifest.placeholder_reason = None;
    manifest.signed_at_utc = Some(Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    write_manifest(registry_dir, &manifest)?;
    eprintln!(
        "flipped placeholder=false on {}; signed_at_utc={}",
        registry_dir.join(REGISTRY_MANIFEST_FILENAME).display(),
        manifest.signed_at_utc.as_deref().unwrap_or("(none)")
    );
    Ok(())
}

fn write_manifest(registry_dir: &std::path::Path, manifest: &RegistryManifest) -> Result<()> {
    let bytes = canonical_bytes(manifest).context("could not JCS-canonicalize manifest")?;
    let path = registry_dir.join(REGISTRY_MANIFEST_FILENAME);
    std::fs::write(&path, &bytes)
        .with_context(|| format!("could not write {}", path.display()))?;
    Ok(())
}
