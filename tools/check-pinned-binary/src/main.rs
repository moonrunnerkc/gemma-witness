//! Verifies a sidecar binary against a pinned manifest before launch.
//!
//! Audit finding S-7 hardening: the prior `start.sh` flow only compared
//! `binary --version` to a pinned string, which a malicious replacement on
//! `$PATH` can trivially spoof. This tool hashes the binary at the supplied
//! path with SHA-256 and refuses on any mismatch against the per-target-triple
//! entry in PINNED.json.
//!
//! Exit codes:
//! - 0: hash matched a known-good entry, launch is permitted.
//! - 2: invalid invocation / IO / parse error.
//! - 64: PINNED.json carries `placeholder: true`; the build has not been
//!   audited yet. Use `--allow-local-dev` to bypass for development hosts.
//! - 65: no entry for the host's target triple. Use `--allow-local-dev` to
//!   bypass.
//! - 66: hash mismatch. Use `--allow-local-dev` to bypass.
//!
//! In `--allow-local-dev` mode, any of the soft-fail conditions above print
//! the diagnostic to stderr and exit 0. The release-gate live e2e MUST NOT
//! set that flag.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Parser, Debug)]
#[command(name = "check-pinned-binary")]
#[command(
    about = "Refuses to permit a sidecar launch unless the binary's SHA-256 matches a pinned manifest."
)]
struct Cli {
    /// Path to PINNED.json.
    #[arg(long)]
    pinned: PathBuf,

    /// Path to the binary whose SHA-256 will be checked.
    #[arg(long)]
    binary: PathBuf,

    /// Override the target triple. Default: detected via `rustc -vV` or
    /// `uname` heuristics. Tests use this to exercise per-triple branches
    /// without spawning rustc.
    #[arg(long)]
    target_triple: Option<String>,

    /// If set, soft failures (placeholder pin, no triple entry, hash
    /// mismatch) print the diagnostic and exit 0. Required for local dev on
    /// hosts where no release binary exists yet; never set on a release-gate
    /// path.
    #[arg(long)]
    allow_local_dev: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("check-pinned-binary: {err}");
            ExitCode::from(err.exit_code())
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum CheckError {
    #[error("could not read pinned manifest at {path}: {source}")]
    PinnedIo {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("pinned manifest at {path} did not parse: {source}")]
    PinnedParse {
        path: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("could not read binary at {path}: {source}")]
    BinaryIo {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("could not detect target triple. install rustc or pass --target-triple explicitly: {detail}")]
    NoTriple { detail: String },

    #[error("PINNED.json declares placeholder=true (upstream_commit={commit}); the build has not been audited yet. release.yml will populate a real commit and binary hashes on the next tag. for local development export WITNESS_MISTRALRS_LOCAL_DEV=1 (or pass --allow-local-dev to this tool) to bypass.")]
    Placeholder { commit: String },

    #[error("PINNED.json has no entry for target_triple={triple}. known triples: [{known}]. cargo install --rev {commit} mistralrs-server, take the SHA-256 from `shasum -a 256 $(command -v mistralrs)`, and add it via the release workflow. for local development on an unsupported host, pass --allow-local-dev to bypass.")]
    UnknownTriple {
        triple: String,
        known: String,
        commit: String,
    },

    #[error("binary at {path} has SHA-256 {actual}, but PINNED.json expects {expected} for target_triple={triple}. a swapped or rebuilt binary will sign bundles against an inference path you did not audit. reinstall via the pinned cargo install command, or for local development pass --allow-local-dev to bypass.")]
    HashMismatch {
        path: String,
        actual: String,
        expected: String,
        triple: String,
    },
}

impl CheckError {
    fn exit_code(&self) -> u8 {
        match self {
            CheckError::PinnedIo { .. } => 2,
            CheckError::PinnedParse { .. } => 2,
            CheckError::BinaryIo { .. } => 2,
            CheckError::NoTriple { .. } => 2,
            CheckError::Placeholder { .. } => 64,
            CheckError::UnknownTriple { .. } => 65,
            CheckError::HashMismatch { .. } => 66,
        }
    }

    /// True when --allow-local-dev should downgrade this error to a warning.
    fn is_soft(&self) -> bool {
        matches!(
            self,
            CheckError::Placeholder { .. }
                | CheckError::UnknownTriple { .. }
                | CheckError::HashMismatch { .. }
        )
    }
}

#[derive(Debug, Deserialize)]
struct PinnedManifest {
    #[serde(default)]
    schema_version: u32,
    #[serde(default)]
    upstream_commit: String,
    #[serde(default)]
    placeholder: bool,
    #[serde(default)]
    binaries: Vec<PinnedBinary>,
}

#[derive(Debug, Deserialize)]
struct PinnedBinary {
    target_triple: String,
    sha256: String,
}

fn run(cli: &Cli) -> Result<(), CheckError> {
    let manifest = load_manifest(&cli.pinned)?;
    if manifest.schema_version != 1 {
        return Err(CheckError::PinnedParse {
            path: cli.pinned.display().to_string(),
            source: serde::de::Error::custom(format!(
                "schema_version {} not supported (expected 1)",
                manifest.schema_version
            )),
        });
    }
    let triple = match cli.target_triple.clone() {
        Some(t) => t,
        None => detect_target_triple()?,
    };
    let actual_hash = hash_file(&cli.binary)?;

    match decide(&manifest, &triple, &actual_hash, &cli.binary) {
        Ok(()) => {
            println!(
                "ok target_triple={triple} sha256={actual_hash} binary={}",
                cli.binary.display()
            );
            Ok(())
        }
        Err(err) if err.is_soft() && cli.allow_local_dev => {
            eprintln!("WARNING (allow-local-dev): {err}");
            println!(
                "ok-dev target_triple={triple} sha256={actual_hash} binary={}",
                cli.binary.display()
            );
            Ok(())
        }
        Err(err) => Err(err),
    }
}

fn decide(
    manifest: &PinnedManifest,
    triple: &str,
    actual_hash: &str,
    binary_path: &Path,
) -> Result<(), CheckError> {
    if manifest.placeholder {
        return Err(CheckError::Placeholder {
            commit: manifest.upstream_commit.clone(),
        });
    }
    let entry = match manifest.binaries.iter().find(|b| b.target_triple == triple) {
        Some(b) => b,
        None => {
            let known = manifest
                .binaries
                .iter()
                .map(|b| b.target_triple.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(CheckError::UnknownTriple {
                triple: triple.to_string(),
                known,
                commit: manifest.upstream_commit.clone(),
            });
        }
    };
    if entry.sha256 != actual_hash {
        return Err(CheckError::HashMismatch {
            path: binary_path.display().to_string(),
            actual: actual_hash.to_string(),
            expected: entry.sha256.clone(),
            triple: triple.to_string(),
        });
    }
    Ok(())
}

fn load_manifest(path: &Path) -> Result<PinnedManifest, CheckError> {
    let raw = std::fs::read_to_string(path).map_err(|source| CheckError::PinnedIo {
        path: path.display().to_string(),
        source,
    })?;
    serde_json::from_str(&raw).map_err(|source| CheckError::PinnedParse {
        path: path.display().to_string(),
        source,
    })
}

fn hash_file(path: &Path) -> Result<String, CheckError> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|source| CheckError::BinaryIo {
        path: path.display().to_string(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|source| CheckError::BinaryIo {
            path: path.display().to_string(),
            source,
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Detect the host's target triple. Prefers `rustc -vV` for accuracy; falls
/// back to a uname-based map for hosts without a Rust toolchain (a release
/// binary unpacked on a bare server).
fn detect_target_triple() -> Result<String, CheckError> {
    if let Ok(output) = std::process::Command::new("rustc").arg("-vV").output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(line) = stdout.lines().find(|l| l.starts_with("host: ")) {
                return Ok(line.trim_start_matches("host: ").trim().to_string());
            }
        }
    }
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let triple = match (os, arch) {
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        _ => {
            return Err(CheckError::NoTriple {
                detail: format!("unsupported os/arch: {os}/{arch}"),
            });
        }
    };
    Ok(triple.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_with(binaries: Vec<(&str, &str)>, placeholder: bool) -> PinnedManifest {
        PinnedManifest {
            schema_version: 1,
            upstream_commit: "deadbeef".to_string(),
            placeholder,
            binaries: binaries
                .into_iter()
                .map(|(t, s)| PinnedBinary {
                    target_triple: t.to_string(),
                    sha256: s.to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn decide_passes_on_matching_hash() {
        let manifest = manifest_with(vec![("x86_64-unknown-linux-gnu", "abc123")], false);
        decide(
            &manifest,
            "x86_64-unknown-linux-gnu",
            "abc123",
            Path::new("/fake/path"),
        )
        .expect("matching hash must permit launch");
    }

    #[test]
    fn decide_rejects_placeholder_pin() {
        let manifest = manifest_with(vec![], true);
        let err = decide(
            &manifest,
            "x86_64-unknown-linux-gnu",
            "abc123",
            Path::new("/fake/path"),
        )
        .expect_err("placeholder must refuse");
        assert!(matches!(err, CheckError::Placeholder { .. }));
        assert_eq!(err.exit_code(), 64);
    }

    #[test]
    fn decide_rejects_unknown_triple() {
        let manifest = manifest_with(vec![("x86_64-unknown-linux-gnu", "abc123")], false);
        let err = decide(
            &manifest,
            "aarch64-apple-darwin",
            "abc123",
            Path::new("/fake/path"),
        )
        .expect_err("missing triple must refuse");
        assert!(matches!(err, CheckError::UnknownTriple { .. }));
        assert_eq!(err.exit_code(), 65);
    }

    #[test]
    fn decide_rejects_hash_mismatch() {
        let manifest = manifest_with(vec![("x86_64-unknown-linux-gnu", "abc123")], false);
        let err = decide(
            &manifest,
            "x86_64-unknown-linux-gnu",
            "deadbeef",
            Path::new("/fake/path"),
        )
        .expect_err("mismatched hash must refuse");
        assert!(matches!(err, CheckError::HashMismatch { .. }));
        assert_eq!(err.exit_code(), 66);
    }

    #[test]
    fn hash_file_matches_known_vector() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        std::fs::write(&path, b"hello world").unwrap();
        let h = hash_file(&path).expect("hash succeeds");
        assert_eq!(
            h,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}
