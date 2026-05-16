//! Sigstore signature gate for the fingerprint registry envelope.
//!
//! The envelope's JCS-canonical bytes are signed by `cosign sign-blob`
//! at release time using the same keyless OIDC identity that signs
//! `SHASUMS256.txt` in `.github/workflows/release.yml`. Verification
//! against the pinned Fulcio root happens offline: no Rekor fetch, no
//! TUF refresh, no internet.
//!
//! The pinned cert-identity policy mirrors `RELEASE.md` §"Trust anchors".
//! Updating that block requires updating the constants here. The two are
//! load-bearing for each other; out-of-sync values mean either the
//! release workflow signs an envelope a verifier refuses, or a verifier
//! accepts an identity the workflow never uses.

use crate::{canonical_bytes, RegistryManifest, VerifyError, REGISTRY_BUNDLE_FILENAME};
use sigstore_trust_root::{TrustedRoot, SIGSTORE_PRODUCTION_TRUSTED_ROOT};
use sigstore_verify::types::Bundle;
use sigstore_verify::{VerificationPolicy, Verifier};
use std::path::Path;

/// OIDC issuer that GitHub Actions presents to Fulcio. Must match
/// `RELEASE.md` §"Trust anchors". Out-of-sync values mean signature
/// verification rejects a legitimately-signed envelope.
pub const OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Workflow path that the cert identity must point to. The full SAN URI
/// emitted by GitHub Actions keyless cosign has the shape
/// `<CERT_IDENTITY_PREFIX>@refs/tags/v<X.Y.Z>`; this constant covers
/// everything up to (and including) the `@`. `sigstore-verify` 0.7
/// matches the policy `identity` field by exact-string equality, so the
/// regex match against the tag suffix is done in [`identity_is_release`]
/// after the Sigstore stack returns the certificate's identity.
pub const CERT_IDENTITY_PREFIX: &str =
    "https://github.com/moonrunnerkc/gemma-witness/.github/workflows/release.yml@refs/tags/v";

/// Returns `true` when `identity` is a SAN URI produced by a tagged
/// release run of `release.yml`. The check is prefix + non-empty
/// remainder; tags follow `v<major>.<minor>.<patch>` per `RELEASE.md`,
/// and any non-empty remainder is acceptable here so that point releases,
/// release candidates, and pre-1.0 tags all match.
pub fn identity_is_release(identity: &str) -> bool {
    identity.len() > CERT_IDENTITY_PREFIX.len() && identity.starts_with(CERT_IDENTITY_PREFIX)
}

/// Read the `registry-manifest.sigstore` bundle from disk and verify it
/// covers the given envelope. Returns `Ok(())` only when:
///
/// 1. The bundle parses as a Sigstore bundle.
/// 2. The bundle's signing certificate chains to the pinned Sigstore
///    production trust root.
/// 3. The certificate's OIDC issuer extension matches [`OIDC_ISSUER`].
/// 4. The certificate's SAN URI satisfies [`identity_is_release`].
/// 5. The signature is valid over the envelope's JCS-canonical bytes.
///
/// Any failure returns [`VerifyError::SignatureRejected`] with the
/// underlying detail surfaced in the error string. The caller is
/// expected to render this directly to the user (build-script panic
/// message or verifier UI line).
pub fn verify_signature(
    registry_dir: &Path,
    manifest: &RegistryManifest,
) -> Result<(), VerifyError> {
    if manifest.placeholder {
        return Err(VerifyError::PlaceholderEnvelope);
    }
    let bundle_path = registry_dir.join(REGISTRY_BUNDLE_FILENAME);
    if !bundle_path.exists() {
        return Err(VerifyError::MissingSignatureArtifact {
            file: REGISTRY_BUNDLE_FILENAME,
        });
    }
    let bundle_json = std::fs::read_to_string(&bundle_path).map_err(|source| VerifyError::Io {
        path: bundle_path.clone(),
        source,
    })?;
    let bundle = Bundle::from_json(&bundle_json).map_err(|err| VerifyError::SignatureRejected {
        detail: format!("could not parse {REGISTRY_BUNDLE_FILENAME}: {err}"),
    })?;
    let trusted_root = TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT).map_err(|err| {
        VerifyError::SignatureRejected {
            detail: format!(
                "vendored Sigstore production trust root failed to load: {err}. \
                 this is a bug in sigstore-trust-root or its bundled data; rebuild the workspace"
            ),
        }
    })?;
    let payload = canonical_bytes(manifest).map_err(|err| VerifyError::SignatureRejected {
        detail: format!("could not JCS-canonicalize envelope: {err}"),
    })?;

    // The Sigstore stack validates the cert chain, SCT, Rekor inclusion,
    // and the signature itself. We pass only the OIDC issuer in the
    // policy because the SAN URI varies per tag; the prefix check below
    // applies the tag-pattern constraint that release.yml encodes.
    let policy = VerificationPolicy::default().require_issuer(OIDC_ISSUER);
    let verifier = Verifier::new(&trusted_root);
    let result = verifier
        .verify(payload.as_slice(), &bundle, &policy)
        .map_err(|err| VerifyError::SignatureRejected {
            detail: err.to_string(),
        })?;
    if !result.success {
        return Err(VerifyError::SignatureRejected {
            detail: "sigstore-verify returned success=false".to_string(),
        });
    }
    let identity = result.identity.as_deref().ok_or_else(|| VerifyError::SignatureRejected {
        detail: "verified certificate did not surface a SAN identity. \
                 the cosign sign-blob run that produced this envelope was not from a tagged release workflow"
            .to_string(),
    })?;
    if !identity_is_release(identity) {
        return Err(VerifyError::SignatureRejected {
            detail: format!(
                "certificate identity {identity} does not match the pinned release.yml workflow path. \
                 expected prefix {CERT_IDENTITY_PREFIX}<tag>. \
                 update RELEASE.md and CERT_IDENTITY_PREFIX in lockstep if the repository moved or the workflow was renamed"
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_envelope_is_refused_by_signature_gate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = RegistryManifest {
            schema_version: crate::REGISTRY_MANIFEST_SCHEMA_VERSION,
            placeholder: true,
            placeholder_reason: Some("test".to_string()),
            covered_files: vec![],
            signed_at_utc: None,
        };
        let err = verify_signature(dir.path(), &manifest).expect_err("placeholder must refuse");
        assert!(
            matches!(err, VerifyError::PlaceholderEnvelope),
            "expected PlaceholderEnvelope, got {err:?}"
        );
    }

    #[test]
    fn missing_bundle_is_a_typed_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = RegistryManifest {
            schema_version: crate::REGISTRY_MANIFEST_SCHEMA_VERSION,
            placeholder: false,
            placeholder_reason: None,
            covered_files: vec![],
            signed_at_utc: Some("2026-05-15T00:00:00Z".to_string()),
        };
        let err = verify_signature(dir.path(), &manifest).expect_err("must fail without bundle");
        assert!(
            matches!(
                err,
                VerifyError::MissingSignatureArtifact {
                    file: REGISTRY_BUNDLE_FILENAME
                }
            ),
            "expected MissingSignatureArtifact, got {err:?}"
        );
    }

    #[test]
    fn identity_prefix_pins_release_yml_workflow_path() {
        // Defense against drift: if release.yml is renamed or the org/repo
        // changes, CERT_IDENTITY_PREFIX must move with it. A failing test
        // here points the maintainer at both this file and RELEASE.md.
        assert!(CERT_IDENTITY_PREFIX.contains("/moonrunnerkc/gemma-witness/"));
        assert!(CERT_IDENTITY_PREFIX.contains("/.github/workflows/release.yml"));
        assert!(CERT_IDENTITY_PREFIX.ends_with("@refs/tags/v"));
    }

    #[test]
    fn identity_is_release_matches_real_and_rejects_imposters() {
        assert!(identity_is_release(
            "https://github.com/moonrunnerkc/gemma-witness/.github/workflows/release.yml@refs/tags/v0.4.0"
        ));
        assert!(identity_is_release(
            "https://github.com/moonrunnerkc/gemma-witness/.github/workflows/release.yml@refs/tags/v1.0.0-rc.1"
        ));
        assert!(!identity_is_release(
            "https://github.com/moonrunnerkc/gemma-witness/.github/workflows/release.yml@refs/tags/v"
        ));
        assert!(!identity_is_release(
            "https://github.com/moonrunnerkc/gemma-witness/.github/workflows/ci.yml@refs/tags/v0.4.0"
        ));
        assert!(!identity_is_release(
            "https://github.com/attacker/gemma-witness/.github/workflows/release.yml@refs/tags/v0.4.0"
        ));
    }
}
