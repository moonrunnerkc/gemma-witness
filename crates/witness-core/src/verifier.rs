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
use crate::signing_ecdsa::verify_pem as verify_pem_ecdsa_p256;

/// One known-good model fingerprint accepted by the verifier.
///
/// Audit finding V-4 widened the verifier check from "SHA-256 only" to a
/// `(model_id, revision, sha256)` triple. The Rust verifier now accepts a
/// slice of these so a bundle that claims `model_id = "evil/model"` with a
/// real registered SHA-256 fails the row even though the hash is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownFingerprint {
    pub model_id: String,
    pub revision: String,
    pub sha256: String,
}

impl From<crate::manifest::ModelFingerprint> for KnownFingerprint {
    fn from(value: crate::manifest::ModelFingerprint) -> Self {
        Self {
            model_id: value.model_id,
            revision: value.revision,
            sha256: value.sha256,
        }
    }
}

/// Versions of `manifest_version` this verifier implementation supports.
///
/// v1 is the original Ed25519-only manifest shape. v2 widens
/// `signer.algorithm` to allow `ecdsa-p256` and adds an optional
/// `signer.attestation` blob for hardware-backed key provenance. The
/// verifier accepts both; per-version validity is enforced in
/// [`check_signature`].
pub const SUPPORTED_MANIFEST_VERSIONS: &[u32] = &[1, 2];

/// The only value `signature.json.signed_payload` may take.
const EXPECTED_SIGNED_PAYLOAD: &str = bundle_paths::MANIFEST;
/// The only value `signature.json.canonicalization` may take.
const EXPECTED_CANONICALIZATION: &str = "rfc8785";

/// Wire string for Ed25519 in both `signature.algorithm` and
/// `manifest.signer.algorithm`.
const ALGORITHM_ED25519: &str = "ed25519";
/// Wire string for ECDSA P-256, permitted only in v2 bundles. The actual
/// verification implementation lands in a follow-up; until then, a bundle
/// declaring this algorithm fails the signature row with a clear "not yet
/// implemented" message rather than being misread as Ed25519.
const ALGORITHM_ECDSA_P256: &str = "ecdsa-p256";

/// Maximum length (in characters) of the base64-encoded attestation
/// payload accepted by the verifier. Caps the decoded blob at 16 KiB,
/// well above what any current hardware attestation format produces
/// (Apple SEP attestations: ~700 B, TPM2 quotes: ~2 KiB). Bounds memory
/// during parsing and refuses denial-of-service via oversized bundles.
pub const MAX_ATTESTATION_PAYLOAD_B64_LEN: usize = 22_528;

/// Returns the set of `signature.algorithm` and `manifest.signer.algorithm`
/// values permitted for a given `manifest_version`.
fn algorithms_permitted_for_version(version: u32) -> &'static [&'static str] {
    match version {
        1 => &[ALGORITHM_ED25519],
        2 => &[ALGORITHM_ED25519, ALGORITHM_ECDSA_P256],
        _ => &[],
    }
}

/// Outcome of a bundle verification run. Every step is a typed boolean plus
/// a detail string suitable for surfacing to a UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    pub manifest_parsed: bool,
    pub signature_valid: bool,
    pub assets_untampered: bool,
    pub model_fingerprint_known: bool,
    /// When `manifest.amends` is absent this stays `true` (vacuously).
    /// When it is present this asserts the amending bundle's
    /// `signer.key_id` matches the back-linked `original_signer_key_id`.
    pub amendment_chain_valid: bool,
    pub details: Vec<String>,
}

impl VerificationReport {
    /// True when every check passed.
    pub fn is_ok(&self) -> bool {
        self.manifest_parsed
            && self.signature_valid
            && self.assets_untampered
            && self.model_fingerprint_known
            && self.amendment_chain_valid
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
    known_fingerprints: &[KnownFingerprint],
) -> Result<VerificationReport, WitnessCoreError> {
    let entries = read_bundle(path)?;
    let manifest_bytes =
        entries
            .get(bundle_paths::MANIFEST)
            .ok_or_else(|| WitnessCoreError::BundleStructure {
                detail: format!(
                    "bundle at {path:?} is missing {}; not a valid .witness archive",
                    bundle_paths::MANIFEST
                ),
            })?;
    let signature_bytes =
        entries
            .get(bundle_paths::SIGNATURE)
            .ok_or_else(|| WitnessCoreError::BundleStructure {
                detail: format!("bundle at {path:?} is missing {}", bundle_paths::SIGNATURE),
            })?;

    // Route on manifest_version before attempting full deserialization. A v2
    // bundle deserialized into the v1 Manifest struct would otherwise surface
    // as a generic serde error that hides the real cause.
    let manifest_version = peek_manifest_version(manifest_bytes)?;
    if !SUPPORTED_MANIFEST_VERSIONS.contains(&manifest_version) {
        return Err(WitnessCoreError::BundleStructure {
            detail: format!(
                "manifest_version {manifest_version} is not supported by this verifier. \
                 supported versions: {:?}. obtain a newer verifier or regenerate the bundle \
                 with a compatible capture app.",
                SUPPORTED_MANIFEST_VERSIONS
            ),
        });
    }

    let manifest: Manifest = serde_json::from_slice(manifest_bytes)
        .map_err(|source| WitnessCoreError::Serialize { source })?;
    let signature_doc: SignatureDocument = serde_json::from_slice(signature_bytes)
        .map_err(|source| WitnessCoreError::Serialize { source })?;

    let mut details: Vec<String> = Vec::new();
    let mut report = VerificationReport {
        manifest_parsed: true,
        signature_valid: false,
        assets_untampered: false,
        model_fingerprint_known: false,
        amendment_chain_valid: true,
        details: Vec::new(),
    };

    report.signature_valid = check_signature(&manifest, &signature_doc, &mut details);
    report.assets_untampered = check_assets(&manifest, &entries, &mut details)
        && check_no_extra_entries(&manifest, &entries, &mut details);
    report.model_fingerprint_known = check_fingerprint(&manifest, known_fingerprints, &mut details);
    report.amendment_chain_valid = check_amendment_chain(&manifest, &mut details);

    report.details = details;
    Ok(report)
}

/// Public alias of [`verify_bundle`] used by amendment-chain regression tests.
/// Today the amendment-chain check is one row of the standard report; if it
/// ever moves to a richer multi-bundle view, this is the call site that grows.
pub fn verify_amendment_chain(
    path: &Path,
    known_fingerprints: &[KnownFingerprint],
) -> Result<VerificationReport, WitnessCoreError> {
    verify_bundle(path, known_fingerprints)
}

/// When `manifest.amends` is present, assert the amending bundle's signer
/// matches the back-linked `original_signer_key_id`. Without this check, any
/// keypair could forge an "amendment" of any other bundle.
///
/// Returns `true` when the field is absent (no chain to check) or when the
/// keys match. Returns `false` and pushes a detail message when they do not.
fn check_amendment_chain(manifest: &Manifest, details: &mut Vec<String>) -> bool {
    let Some(amends) = manifest.amends.as_ref() else {
        return true;
    };
    if amends.original_signer_key_id == manifest.signer.key_id {
        return true;
    }
    details.push(format!(
        "manifest.amends.original_signer_key_id \"{}\" does not match this bundle's signer.key_id \"{}\". \
         the amendment was signed by a different key than the original it claims to correct. \
         a reviewer should treat this as an independent claim rather than a continuation of the chain.",
        amends.original_signer_key_id, manifest.signer.key_id
    ));
    false
}

/// Reject any ZIP entry not bound by the signature.
///
/// The signed manifest only commits to `manifest.json` (via the signature
/// itself) and to each `assets[].path` (via the asset hash list). Anything
/// else in the ZIP - extra images, an injected `index.html`, a poisoned
/// `public_key.pem` - is not covered by the signature and would be a vector
/// for "smuggle a file into a signed bundle" attacks if accepted.
///
/// The only other entry conforming bundles MAY contain is `signature.json`,
/// which is checked separately by [`check_signature`]. Refusing extras here
/// guarantees the bundle is exactly the set of bytes the signer attested to.
fn check_no_extra_entries(
    manifest: &Manifest,
    entries: &BTreeMap<String, Vec<u8>>,
    details: &mut Vec<String>,
) -> bool {
    let mut allowed: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    allowed.insert(bundle_paths::MANIFEST.to_string());
    allowed.insert(bundle_paths::SIGNATURE.to_string());
    for asset in &manifest.assets {
        allowed.insert(asset.path.clone());
    }

    let mut all_ok = true;
    for name in entries.keys() {
        if !allowed.contains(name) {
            details.push(format!(
                "ZIP entry {name:?} is not bound by the signature. \
                 conforming bundles contain only manifest.json, signature.json, and the asset \
                 paths listed in manifest.assets. extras may have been appended to a legitimately \
                 signed bundle and must not be trusted."
            ));
            all_ok = false;
        }
    }
    all_ok
}

/// Read only `manifest_version` from a manifest byte slice without fully
/// deserializing into [`Manifest`].
fn peek_manifest_version(bytes: &[u8]) -> Result<u32, WitnessCoreError> {
    #[derive(serde::Deserialize)]
    struct VersionPeek {
        manifest_version: u32,
    }
    let peek: VersionPeek =
        serde_json::from_slice(bytes).map_err(|source| WitnessCoreError::BundleStructure {
            detail: format!(
                "manifest.json is missing the manifest_version field or it is not a u32: {source}"
            ),
        })?;
    Ok(peek.manifest_version)
}

fn check_signature(
    manifest: &Manifest,
    signature_doc: &SignatureDocument,
    details: &mut Vec<String>,
) -> bool {
    let permitted = algorithms_permitted_for_version(manifest.manifest_version);
    if !permitted.contains(&signature_doc.algorithm.as_str()) {
        details.push(format!(
            "signature.algorithm is \"{}\"; manifest_version {} permits only {:?}. \
             the bundle may be malformed or produced by a verifier-incompatible capture app.",
            signature_doc.algorithm, manifest.manifest_version, permitted
        ));
        return false;
    }
    if !permitted.contains(&manifest.signer.algorithm.as_str()) {
        details.push(format!(
            "manifest.signer.algorithm is \"{}\"; manifest_version {} permits only {:?}. \
             the bundle may be malformed or produced by a verifier-incompatible capture app.",
            manifest.signer.algorithm, manifest.manifest_version, permitted
        ));
        return false;
    }
    if signature_doc.algorithm != manifest.signer.algorithm {
        details.push(format!(
            "signature.algorithm \"{}\" does not match manifest.signer.algorithm \"{}\". \
             the two must agree; a mismatch indicates the signature was copied from a different bundle.",
            signature_doc.algorithm, manifest.signer.algorithm
        ));
        return false;
    }
    if manifest.manifest_version == 1 && manifest.signer.attestation.is_some() {
        details.push(
            "manifest.signer.attestation is present on a v1 manifest. the attestation blob is a v2-only field; a v1 bundle that carries it is malformed.".to_string()
        );
        return false;
    }
    if let Some(att) = manifest.signer.attestation.as_ref() {
        if att.payload_b64.len() > MAX_ATTESTATION_PAYLOAD_B64_LEN {
            details.push(format!(
                "manifest.signer.attestation.payload_b64 is {} bytes (base64-encoded); the cap is {} bytes (= 16 KiB decoded). \
                 oversized attestations are refused to bound verifier memory and to make denial-of-service via \
                 bloated bundles impossible.",
                att.payload_b64.len(),
                MAX_ATTESTATION_PAYLOAD_B64_LEN
            ));
            return false;
        }
    }
    if signature_doc.canonicalization != EXPECTED_CANONICALIZATION {
        details.push(format!(
            "signature.canonicalization is \"{}\"; expected \"{EXPECTED_CANONICALIZATION}\". \
             the manifest must be canonicalized per RFC 8785.",
            signature_doc.canonicalization
        ));
        return false;
    }
    if signature_doc.signed_payload != EXPECTED_SIGNED_PAYLOAD {
        details.push(format!(
            "signature.signed_payload is \"{}\"; expected \"{EXPECTED_SIGNED_PAYLOAD}\". \
             this verifier only signs over manifest.json.",
            signature_doc.signed_payload
        ));
        return false;
    }
    if signature_doc.key_id != manifest.signer.key_id {
        details.push(format!(
            "signature.key_id \"{}\" does not match manifest.signer.key_id \"{}\". \
             the signature may have been copied from a different bundle.",
            signature_doc.key_id, manifest.signer.key_id
        ));
        return false;
    }

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
    match manifest.signer.algorithm.as_str() {
        ALGORITHM_ED25519 => verify_ed25519(
            &manifest.signer.public_key_pem,
            &canonical,
            &signature_bytes,
            details,
        ),
        ALGORITHM_ECDSA_P256 => verify_ecdsa_p256(
            &manifest.signer.public_key_pem,
            &canonical,
            &signature_bytes,
            details,
        ),
        other => {
            details.push(format!(
                "manifest.signer.algorithm \"{other}\" reached signature dispatch but no backend matches. this is a verifier bug; report it."
            ));
            false
        }
    }
}

fn verify_ed25519(
    public_key_pem: &str,
    canonical_manifest: &[u8],
    signature_bytes: &[u8],
    details: &mut Vec<String>,
) -> bool {
    if signature_bytes.len() != 64 {
        details.push(format!(
            "Ed25519 signature was {} bytes; expected 64. bundle is malformed",
            signature_bytes.len()
        ));
        return false;
    }
    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(signature_bytes);
    match verify_pem(public_key_pem, canonical_manifest, &sig_array) {
        Ok(()) => true,
        Err(err) => {
            details.push(format!("signature did not verify: {err}"));
            false
        }
    }
}

fn verify_ecdsa_p256(
    public_key_pem: &str,
    canonical_manifest: &[u8],
    signature_bytes: &[u8],
    details: &mut Vec<String>,
) -> bool {
    match verify_pem_ecdsa_p256(public_key_pem, canonical_manifest, signature_bytes) {
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
    known_fingerprints: &[KnownFingerprint],
    details: &mut Vec<String>,
) -> bool {
    let fp = &manifest.assertions.model_fingerprint;
    let Some(by_hash) = known_fingerprints.iter().find(|f| f.sha256 == fp.sha256) else {
        details.push(format!(
            "model fingerprint {sha} for {mid}@{rev} is not on the known-good list. \
             update the fingerprint registry after publishing or approving this model revision",
            sha = fp.sha256,
            mid = fp.model_id,
            rev = fp.revision
        ));
        return false;
    };
    if by_hash.model_id != fp.model_id || by_hash.revision != fp.revision {
        details.push(format!(
            "model fingerprint {sha} is registered but for {known_id}@{known_rev}, \
             not the manifest's claimed {claim_id}@{claim_rev}. \
             a registered SHA-256 must match the registered (model_id, revision) tuple to be trusted; \
             a divergence indicates the bundle is claiming a model_id the registry does not own",
            sha = fp.sha256,
            known_id = by_hash.model_id,
            known_rev = by_hash.revision,
            claim_id = fp.model_id,
            claim_rev = fp.revision
        ));
        return false;
    }
    true
}
