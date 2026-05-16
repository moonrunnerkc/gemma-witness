//! Canonicalizes and verifies the integrity of the
//! `inference/fingerprints/` registry against a Sigstore-signed envelope.
//!
//! Two independent gates live in this crate:
//!
//! 1. **Content gate.** Every file the envelope claims to cover is hashed
//!    from disk and compared against the SHA-256 the envelope records.
//!    A mismatch on a single byte fails the gate. This protects against
//!    a tampered registry whose envelope was signed honestly but where a
//!    later edit to a fingerprint file slipped past review.
//! 2. **Signature gate.** The envelope's RFC 8785 JCS-canonical bytes are
//!    verified against a Sigstore bundle (cosign `--bundle` output) that
//!    must chain to a pinned Fulcio root and present the OIDC certificate
//!    identity recorded in `RELEASE.md`. Today the gate is active only
//!    when `placeholder=false`; a placeholder envelope ships before the
//!    signing workflow has produced its first signature, identical to the
//!    pattern used by `inference/mistralrs-sidecar/PINNED.json`.
//!
//! Both gates run at compile time via `crates/witness-fingerprints/build.rs`
//! and at verifier load time via `apps/verifier/src/known-fingerprints.ts`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// On-disk filename of the canonical envelope. Lives at the root of
/// `inference/fingerprints/`.
pub const REGISTRY_MANIFEST_FILENAME: &str = "registry-manifest.json";

/// On-disk filename of the cosign Sigstore bundle covering the envelope.
/// Produced by `cosign sign-blob --bundle <file>` in CI.
pub const REGISTRY_BUNDLE_FILENAME: &str = "registry-manifest.sigstore";

/// Schema version of the envelope itself. Bump when the envelope's field
/// set changes in a way an older verifier cannot tolerate.
pub const REGISTRY_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// The canonical envelope. JCS-canonical bytes of this struct are the
/// payload covered by the Sigstore signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryManifest {
    pub schema_version: u32,
    /// `true` until the signing workflow runs for the first time and
    /// publishes `registry-manifest.sigstore`. `false` in a production
    /// build. Verifiers refuse to use a placeholder envelope without a
    /// loud warning surface.
    pub placeholder: bool,
    /// Human-readable explanation rendered alongside the warning when
    /// `placeholder=true`. Omitted once the envelope is signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder_reason: Option<String>,
    /// Sorted by `path` so two captures of the same on-disk state produce
    /// byte-identical canonical bytes.
    pub covered_files: Vec<CoveredFile>,
    /// RFC 3339 UTC timestamp of the signing event, or `None` for a
    /// placeholder envelope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_at_utc: Option<String>,
}

/// One file covered by the envelope. `path` is relative to
/// `inference/fingerprints/`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoveredFile {
    pub path: String,
    pub sha256: String,
}

/// Errors surfaced by this crate. Each variant carries enough context to
/// be actionable in a build-script panic or a verifier UI line.
#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("could not read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("registry manifest at {path} did not parse as JSON: {source}")]
    ManifestParse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("registry manifest uses schema_version {found}; this build understands {expected}. rebuild after updating witness-fingerprint-verify")]
    ManifestSchemaMismatch { found: u32, expected: u32 },

    #[error("registry manifest covers {expected} files but {found} matching files exist on disk. run tools/sign-fingerprints recompute to regenerate the envelope")]
    CoverageCountMismatch { expected: usize, found: usize },

    #[error("registry file {path} is on disk but not listed in the envelope. run tools/sign-fingerprints recompute to include it")]
    UncoveredFile { path: PathBuf },

    #[error("registry file {path} appears in the envelope but is missing from disk")]
    MissingFile { path: PathBuf },

    #[error("registry file {path} hash mismatch: envelope claims {expected}, disk has {actual}. either the envelope is stale (run tools/sign-fingerprints recompute) or the file was edited after signing (investigate)")]
    HashMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },

    #[error("registry envelope is still a placeholder. the signing workflow has not yet produced registry-manifest.sigstore. for development this is expected; production builds must reject")]
    PlaceholderEnvelope,

    #[error("registry envelope claims placeholder=false but {file} is missing. either re-run the signing workflow or revert the envelope to placeholder=true")]
    MissingSignatureArtifact { file: &'static str },

    #[error("registry envelope signature did not verify: {detail}. either the envelope was tampered with after signing, or the verifier's pinned Fulcio root / OIDC identity policy is out of date with RELEASE.md")]
    SignatureRejected { detail: String },
}

/// Canonical bytes of the envelope. Use these as the payload to sign and
/// the bytes to recompute when verifying a Sigstore bundle.
pub fn canonical_bytes(manifest: &RegistryManifest) -> Result<Vec<u8>, serde_json::Error> {
    serde_jcs::to_vec(manifest)
}

/// Hash every regular file under `registry_dir` (non-recursively, skipping
/// the envelope and the Sigstore bundle themselves) and emit a fresh
/// `RegistryManifest` covering them.
///
/// The output is deterministic: rows are sorted by `path`. Run this from
/// `tools/sign-fingerprints recompute` whenever a new fingerprint lands.
pub fn compute_manifest(registry_dir: &Path) -> Result<RegistryManifest, VerifyError> {
    let mut covered = Vec::new();
    let read_dir = std::fs::read_dir(registry_dir).map_err(|source| VerifyError::Io {
        path: registry_dir.to_path_buf(),
        source,
    })?;
    for entry in read_dir {
        let entry = entry.map_err(|source| VerifyError::Io {
            path: registry_dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name == REGISTRY_MANIFEST_FILENAME || name == REGISTRY_BUNDLE_FILENAME {
            continue;
        }
        let bytes = std::fs::read(&path).map_err(|source| VerifyError::Io {
            path: path.clone(),
            source,
        })?;
        let sha = Sha256::digest(&bytes);
        covered.push(CoveredFile {
            path: name.to_string(),
            sha256: hex::encode(sha),
        });
    }
    covered.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(RegistryManifest {
        schema_version: REGISTRY_MANIFEST_SCHEMA_VERSION,
        placeholder: true,
        placeholder_reason: Some(
            "registry-manifest.sigstore has not been produced yet. Run .github/workflows/sign-fingerprints.yml to flip placeholder=false and attach the cosign bundle.".to_string(),
        ),
        covered_files: covered,
        signed_at_utc: None,
    })
}

/// Read the envelope JSON from disk and parse it. Performs schema-version
/// gating but no content or signature checks.
pub fn load_manifest(registry_dir: &Path) -> Result<RegistryManifest, VerifyError> {
    let path = registry_dir.join(REGISTRY_MANIFEST_FILENAME);
    let raw = std::fs::read_to_string(&path).map_err(|source| VerifyError::Io {
        path: path.clone(),
        source,
    })?;
    let manifest: RegistryManifest = serde_json::from_str(&raw).map_err(|source| {
        VerifyError::ManifestParse {
            path: path.clone(),
            source,
        }
    })?;
    if manifest.schema_version != REGISTRY_MANIFEST_SCHEMA_VERSION {
        return Err(VerifyError::ManifestSchemaMismatch {
            found: manifest.schema_version,
            expected: REGISTRY_MANIFEST_SCHEMA_VERSION,
        });
    }
    Ok(manifest)
}

/// Cross-check the envelope against on-disk state. Every file the
/// envelope covers must exist with the recorded SHA-256, and no extra
/// fingerprint files may exist on disk that the envelope does not cover.
pub fn verify_consistency(
    registry_dir: &Path,
    manifest: &RegistryManifest,
) -> Result<(), VerifyError> {
    let on_disk = compute_manifest(registry_dir)?;
    if on_disk.covered_files.len() != manifest.covered_files.len() {
        return Err(VerifyError::CoverageCountMismatch {
            expected: manifest.covered_files.len(),
            found: on_disk.covered_files.len(),
        });
    }
    for disk_row in &on_disk.covered_files {
        let env_row = manifest
            .covered_files
            .iter()
            .find(|r| r.path == disk_row.path)
            .ok_or_else(|| VerifyError::UncoveredFile {
                path: registry_dir.join(&disk_row.path),
            })?;
        if env_row.sha256 != disk_row.sha256 {
            return Err(VerifyError::HashMismatch {
                path: registry_dir.join(&disk_row.path),
                expected: env_row.sha256.clone(),
                actual: disk_row.sha256.clone(),
            });
        }
    }
    for env_row in &manifest.covered_files {
        if !on_disk
            .covered_files
            .iter()
            .any(|r| r.path == env_row.path)
        {
            return Err(VerifyError::MissingFile {
                path: registry_dir.join(&env_row.path),
            });
        }
    }
    Ok(())
}

pub mod signature;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn compute_manifest_skips_envelope_and_bundle() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("a.json"), b"{\"x\":1}").expect("write a");
        fs::write(dir.path().join("b.json"), b"{\"y\":2}").expect("write b");
        fs::write(dir.path().join(REGISTRY_MANIFEST_FILENAME), b"ignored")
            .expect("write manifest");
        fs::write(dir.path().join(REGISTRY_BUNDLE_FILENAME), b"ignored").expect("write bundle");

        let manifest = compute_manifest(dir.path()).expect("compute");
        assert_eq!(manifest.covered_files.len(), 2);
        let paths: Vec<_> = manifest
            .covered_files
            .iter()
            .map(|r| r.path.as_str())
            .collect();
        assert_eq!(paths, vec!["a.json", "b.json"]);
    }

    #[test]
    fn compute_manifest_is_deterministic() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("z.json"), b"z").expect("write z");
        fs::write(dir.path().join("a.json"), b"a").expect("write a");
        let first = compute_manifest(dir.path()).expect("compute");
        let second = compute_manifest(dir.path()).expect("compute");
        assert_eq!(
            canonical_bytes(&first).expect("canon"),
            canonical_bytes(&second).expect("canon"),
        );
        assert_eq!(
            first.covered_files[0].path, "a.json",
            "rows must be sorted by path"
        );
    }

    #[test]
    fn verify_consistency_passes_when_disk_matches_envelope() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("a.json"), b"a").expect("write a");
        let manifest = compute_manifest(dir.path()).expect("compute");
        verify_consistency(dir.path(), &manifest).expect("consistency");
    }

    #[test]
    fn verify_consistency_rejects_edited_file() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("a.json"), b"a").expect("write a");
        let manifest = compute_manifest(dir.path()).expect("compute");
        fs::write(dir.path().join("a.json"), b"a-edited").expect("rewrite a");
        let err = verify_consistency(dir.path(), &manifest).expect_err("must fail");
        assert!(
            matches!(err, VerifyError::HashMismatch { .. }),
            "expected HashMismatch, got {err:?}"
        );
    }

    #[test]
    fn verify_consistency_rejects_uncovered_file() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("a.json"), b"a").expect("write a");
        let manifest = compute_manifest(dir.path()).expect("compute");
        fs::write(dir.path().join("b.json"), b"b").expect("write b after sign");
        let err = verify_consistency(dir.path(), &manifest).expect_err("must fail");
        assert!(matches!(
            err,
            VerifyError::CoverageCountMismatch { .. } | VerifyError::UncoveredFile { .. }
        ));
    }

    #[test]
    fn verify_consistency_rejects_missing_file() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("a.json"), b"a").expect("write a");
        let manifest = compute_manifest(dir.path()).expect("compute");
        fs::remove_file(dir.path().join("a.json")).expect("remove a");
        let err = verify_consistency(dir.path(), &manifest).expect_err("must fail");
        assert!(matches!(
            err,
            VerifyError::CoverageCountMismatch { .. } | VerifyError::MissingFile { .. }
        ));
    }

    #[test]
    fn canonical_bytes_are_jcs_canonical() {
        let manifest = RegistryManifest {
            schema_version: REGISTRY_MANIFEST_SCHEMA_VERSION,
            placeholder: false,
            placeholder_reason: None,
            covered_files: vec![CoveredFile {
                path: "a.json".to_string(),
                sha256: "0".repeat(64),
            }],
            signed_at_utc: Some("2026-05-15T00:00:00Z".to_string()),
        };
        let canonical = canonical_bytes(&manifest).expect("canon");
        let s = std::str::from_utf8(&canonical).expect("utf8");
        let pos_schema = s.find("\"schema_version\"").expect("schema_version present");
        let pos_signed = s.find("\"signed_at_utc\"").expect("signed_at_utc present");
        assert!(
            pos_schema < pos_signed,
            "JCS sorts object keys lexicographically; schema_version must precede signed_at_utc"
        );
    }
}
