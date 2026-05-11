//! Round-trip verifier for `.witness` bundles.
//!
//! Mirrors what the JS verifier on Day 5 will do: parse the manifest,
//! validate the signature against the embedded public key, recompute every
//! asset hash from the raw bytes inside the ZIP, and confirm the model
//! fingerprint is on the known list.

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine;

use crate::bundle_builder::paths as bundle_paths;
use crate::bundle_zip::read_bundle;
use crate::canonical::canonicalize;
use crate::error::WitnessCoreError;
use crate::hashing::hash_bytes_hex;
use crate::manifest::{Manifest, SignatureDocument};
use crate::signing::verify_pem;

/// Outcome of a bundle verification run. Every step is a typed boolean plus
/// a detail string suitable for surfacing to a UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    pub manifest_parsed: bool,
    pub signature_valid: bool,
    pub assets_untampered: bool,
    pub model_fingerprint_known: bool,
    pub details: Vec<String>,
}

impl VerificationReport {
    /// True when every check passed.
    pub fn is_ok(&self) -> bool {
        self.manifest_parsed
            && self.signature_valid
            && self.assets_untampered
            && self.model_fingerprint_known
    }
}

/// Verify a `.witness` bundle at `path` against the list of known model
/// fingerprints (lowercase hex SHA-256s).
///
/// Returns a structured report. Individual check failures are non-fatal:
/// callers receive a populated [`VerificationReport`] regardless. Hard
/// errors (cannot read the ZIP at all, manifest is not JSON) bubble up as
/// [`WitnessCoreError`].
pub fn verify_bundle(
    path: &Path,
    known_fingerprints: &[String],
) -> Result<VerificationReport, WitnessCoreError> {
    let entries = read_bundle(path)?;
    let manifest_bytes = entries
        .get(bundle_paths::MANIFEST)
        .ok_or_else(|| WitnessCoreError::BundleStructure {
            detail: format!(
                "bundle at {path:?} is missing {}; not a valid .witness archive",
                bundle_paths::MANIFEST
            ),
        })?;
    let signature_bytes = entries
        .get(bundle_paths::SIGNATURE)
        .ok_or_else(|| WitnessCoreError::BundleStructure {
            detail: format!("bundle at {path:?} is missing {}", bundle_paths::SIGNATURE),
        })?;

    let manifest: Manifest =
        serde_json::from_slice(manifest_bytes).map_err(|source| WitnessCoreError::Serialize {
            source,
        })?;
    let signature_doc: SignatureDocument =
        serde_json::from_slice(signature_bytes).map_err(|source| WitnessCoreError::Serialize {
            source,
        })?;

    let mut details: Vec<String> = Vec::new();
    let mut report = VerificationReport {
        manifest_parsed: true,
        signature_valid: false,
        assets_untampered: false,
        model_fingerprint_known: false,
        details: Vec::new(),
    };

    report.signature_valid = check_signature(&manifest, &signature_doc, &mut details);
    report.assets_untampered = check_assets(&manifest, &entries, &mut details);
    report.model_fingerprint_known =
        check_fingerprint(&manifest, known_fingerprints, &mut details);

    report.details = details;
    Ok(report)
}

fn check_signature(
    manifest: &Manifest,
    signature_doc: &SignatureDocument,
    details: &mut Vec<String>,
) -> bool {
    let canonical = match canonicalize(manifest) {
        Ok(bytes) => bytes,
        Err(err) => {
            details.push(format!("manifest could not be canonicalized: {err}"));
            return false;
        }
    };
    let signature_bytes = match base64::engine::general_purpose::STANDARD
        .decode(signature_doc.signature_b64.as_bytes())
    {
        Ok(b) => b,
        Err(err) => {
            details.push(format!("signature_b64 was not valid base64: {err}"));
            return false;
        }
    };
    if signature_bytes.len() != 64 {
        details.push(format!(
            "signature was {} bytes; expected 64. bundle is malformed",
            signature_bytes.len()
        ));
        return false;
    }
    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&signature_bytes);
    match verify_pem(&manifest.signer.public_key_pem, &canonical, &sig_array) {
        Ok(()) => true,
        Err(err) => {
            details.push(format!("signature did not verify: {err}"));
            false
        }
    }
}

fn check_assets(
    manifest: &Manifest,
    entries: &BTreeMap<String, Vec<u8>>,
    details: &mut Vec<String>,
) -> bool {
    let mut all_ok = true;
    for asset in &manifest.assets {
        let bytes = match entries.get(&asset.path) {
            Some(b) => b,
            None => {
                details.push(format!(
                    "asset {} listed in manifest is missing from the zip",
                    asset.path
                ));
                all_ok = false;
                continue;
            }
        };
        if bytes.len() as u64 != asset.bytes {
            details.push(format!(
                "asset {} byte length {} does not match manifest claim {}",
                asset.path,
                bytes.len(),
                asset.bytes
            ));
            all_ok = false;
        }
        let actual = hash_bytes_hex(bytes);
        if actual != asset.sha256 {
            details.push(format!(
                "asset {} hash mismatch. manifest said {}, recomputed {}",
                asset.path, asset.sha256, actual
            ));
            all_ok = false;
        }
    }
    all_ok
}

fn check_fingerprint(
    manifest: &Manifest,
    known_fingerprints: &[String],
    details: &mut Vec<String>,
) -> bool {
    let claimed = &manifest.assertions.model_fingerprint.sha256;
    if known_fingerprints.iter().any(|f| f == claimed) {
        true
    } else {
        details.push(format!(
            "model fingerprint {claimed} is not on the known-good list. \
             update apps/verifier/known-fingerprints.json after publishing this model"
        ));
        false
    }
}
