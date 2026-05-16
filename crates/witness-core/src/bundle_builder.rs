//! Build a signed `.witness` bundle from typed inputs.

use std::path::{Path, PathBuf};

use base64::Engine;
use chrono::Utc;

use crate::assertions::audio_fingerprint;
use crate::bundle_zip::{write_bundle, ZipEntry};
use crate::canonical::canonicalize;
use crate::error::WitnessCoreError;
use crate::hashing::{hash_bytes_hex, hash_file_hex};
use crate::manifest::{
    AmendsReference, Assertions, AssetEntry, CaptureEnvironment, ConsistencyVerdict, Manifest,
    ModelFingerprint, ReasoningTrace, SignatureDocument, SignerAttestation, SignerInfo,
    MANIFEST_VERSION,
};
use crate::{IncidentReport, InferenceParameters};

/// In-zip layout constants.
pub mod paths {
    pub const MANIFEST: &str = "manifest.json";
    pub const SIGNATURE: &str = "signature.json";
    pub const AUDIO: &str = "assets/audio.wav";
    pub const REASONING: &str = "assets/reasoning.txt";
    /// Returns the in-zip path for image index `i`.
    pub fn image(i: usize, extension: &str) -> String {
        format!("assets/images/img-{i}.{extension}")
    }
}

/// Caller-supplied inputs to seal a bundle.
#[derive(Debug, Clone)]
pub struct BundleInputs {
    /// Path to the raw audio file on disk.
    pub audio_path: PathBuf,
    /// Paths to the raw image files on disk, in display order.
    pub image_paths: Vec<PathBuf>,
    /// Verbatim thinking-channel bytes from Gemma.
    pub reasoning_trace_bytes: Vec<u8>,
    /// Structured incident report from pass 1.
    pub incident_report: IncidentReport,
    /// Consistency verdict from pass 3.
    pub consistency: ConsistencyVerdict,
    /// Model fingerprint resolved from the embedded registry at
    /// `inference/fingerprints/` (see the `witness-fingerprints` crate).
    pub model_fingerprint: ModelFingerprint,
    /// Capture environment metadata.
    pub capture_environment: CaptureEnvironment,
    /// Device public key PEM and key id.
    pub signer_public_key_pem: String,
    pub signer_key_id: String,
    /// Optional advisory assertion describing the sampling parameters each
    /// inference pass ran with. None today only for callers that have not
    /// adopted the witness-inference helper yet.
    #[allow(clippy::struct_field_names)]
    pub inference_parameters: Option<InferenceParameters>,
    /// Optional reference to a prior bundle that this one supersedes. Set
    /// when issuing a correction or amendment; leave None for a fresh
    /// witness capture.
    pub amends: Option<AmendsReference>,
    /// SHA-256 of the audio bytes the inference pipeline read, hex-encoded.
    /// At seal time `build_and_seal_bundle` recomputes the hash from the
    /// on-disk bytes and aborts if it does not match. Closes the TOCTOU
    /// between inference and seal where a same-user-account process could
    /// swap the on-disk file after Gemma read it but before the user clicked
    /// Seal. None disables the check (e.g., tests that do not run inference).
    pub pinned_audio_sha256: Option<String>,
    /// SHA-256 of each image the inference pipeline read, hex-encoded, in
    /// the same order as [`image_paths`]. The seal step aborts on any
    /// mismatch. See [`pinned_audio_sha256`] for the rationale.
    pub pinned_image_sha256s: Option<Vec<String>>,
}

/// A signer is anything that can produce a signature over a payload and
/// report which algorithm it speaks. The capture app passes the keystore-
/// backed implementation; tests can pass an in-memory signing key.
///
/// Signatures are variable-length to accommodate ECDSA P-256's ASN.1/DER
/// encoding (typically 70 to 72 bytes) alongside Ed25519's fixed 64-byte
/// raw form. The bundle builder uses `algorithm()` to decide the
/// `signer.algorithm` wire string and the minimum `manifest_version`.
pub trait BundleSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, WitnessCoreError>;
    fn algorithm(&self) -> crate::key_provider::SigningAlgorithm;
    /// Optional hardware-backed key attestation document. Returns `Some`
    /// only when the signer can prove its key was minted on a specific
    /// piece of hardware (Apple Secure Enclave, TPM 2.0, NCrypt) AND the
    /// running binary has the entitlement needed to read the attestation.
    /// Unsigned dev binaries on macOS cannot read SEP attestations, so
    /// `Some` is reserved for production builds carrying the right
    /// entitlements. The default impl returns `None`, which lets the
    /// bundle builder omit `signer.attestation` and keeps the v1 wire
    /// shape byte-identical for software signers.
    fn attestation(&self) -> Option<SignerAttestation> {
        None
    }
}

/// Build, sign, and write a `.witness` bundle to `out_path`.
///
/// Returns the bundle id (UUID v4) embedded in the manifest.
///
/// # Errors
/// Any IO, hashing, canonicalization, signing, or ZIP error surfaces as
/// [`WitnessCoreError`].
pub fn build_and_seal_bundle<S: BundleSigner>(
    inputs: &BundleInputs,
    signer: &S,
    out_path: &Path,
) -> Result<String, WitnessCoreError> {
    let audio_bytes =
        std::fs::read(&inputs.audio_path).map_err(|source| WitnessCoreError::AssetRead {
            path: inputs.audio_path.clone(),
            source,
        })?;
    let audio_hash = hash_bytes_hex(&audio_bytes);
    if let Some(pinned) = inputs.pinned_audio_sha256.as_deref() {
        if pinned != audio_hash {
            return Err(WitnessCoreError::AssetTampered {
                path: inputs.audio_path.clone(),
                pinned_sha256: pinned.to_string(),
                seal_sha256: audio_hash,
            });
        }
    }

    // Advisory perceptual fingerprint. A decode failure surfaces as the
    // assertion being omitted, never as a sealing failure: the cryptographic
    // hash above still pins the bytes. We log on stderr to avoid silently
    // hiding decoder bugs.
    let audio_fingerprint = match audio_fingerprint::compute(&audio_bytes) {
        Ok(fp) => Some(fp),
        Err(err) => {
            eprintln!(
                "witness-core: advisory audio fingerprint skipped: {err}. \
                 the cryptographic asset hash is unaffected."
            );
            None
        }
    };

    if let Some(pinned_list) = inputs.pinned_image_sha256s.as_ref() {
        if pinned_list.len() != inputs.image_paths.len() {
            return Err(WitnessCoreError::PinnedImageHashCountMismatch {
                pinned_count: pinned_list.len(),
                seal_count: inputs.image_paths.len(),
            });
        }
    }
    let mut image_blobs: Vec<(String, Vec<u8>, String)> =
        Vec::with_capacity(inputs.image_paths.len());
    for (i, image_path) in inputs.image_paths.iter().enumerate() {
        let extension = image_extension(image_path)?;
        let bytes = std::fs::read(image_path).map_err(|source| WitnessCoreError::AssetRead {
            path: image_path.clone(),
            source,
        })?;
        let hash = hash_bytes_hex(&bytes);
        if let Some(pinned_list) = inputs.pinned_image_sha256s.as_ref() {
            let pinned = &pinned_list[i];
            if pinned != &hash {
                return Err(WitnessCoreError::AssetTampered {
                    path: image_path.clone(),
                    pinned_sha256: pinned.clone(),
                    seal_sha256: hash,
                });
            }
        }
        image_blobs.push((paths::image(i, &extension), bytes, hash));
    }

    let reasoning_hash = hash_bytes_hex(&inputs.reasoning_trace_bytes);

    let mut assets: Vec<AssetEntry> = Vec::with_capacity(2 + image_blobs.len());
    assets.push(AssetEntry {
        path: paths::AUDIO.to_string(),
        media_type: "audio/wav".to_string(),
        sha256: audio_hash,
        bytes: audio_bytes.len() as u64,
    });
    for (path, bytes, hash) in &image_blobs {
        assets.push(AssetEntry {
            path: path.clone(),
            media_type: media_type_for(path),
            sha256: hash.clone(),
            bytes: bytes.len() as u64,
        });
    }
    assets.push(AssetEntry {
        path: paths::REASONING.to_string(),
        media_type: "text/plain; charset=utf-8".to_string(),
        sha256: reasoning_hash.clone(),
        bytes: inputs.reasoning_trace_bytes.len() as u64,
    });

    let bundle_id = uuid::Uuid::new_v4().to_string();
    let signer_algorithm = signer.algorithm();
    // v1 bundles are Ed25519-only. Any non-Ed25519 algorithm forces v2 so
    // the wire form passes the schema's per-version algorithm gate; if a
    // future algorithm needs v3, bump its `minimum_manifest_version`.
    let manifest_version =
        MANIFEST_VERSION.max(signer_algorithm.minimum_manifest_version());
    let manifest = Manifest {
        manifest_version,
        bundle_id: bundle_id.clone(),
        created_at: Utc::now().to_rfc3339(),
        signer: SignerInfo {
            algorithm: signer_algorithm.as_str().to_string(),
            public_key_pem: inputs.signer_public_key_pem.clone(),
            key_id: inputs.signer_key_id.clone(),
            attestation: attestation_for_version(manifest_version, signer.attestation()),
        },
        assets,
        assertions: Assertions {
            model_fingerprint: inputs.model_fingerprint.clone(),
            incident_report: inputs.incident_report.clone(),
            reasoning_trace: ReasoningTrace {
                asset_path: paths::REASONING.to_string(),
                sha256: reasoning_hash,
                bytes: inputs.reasoning_trace_bytes.len() as u64,
            },
            consistency_verdict: inputs.consistency.clone(),
            capture_environment: inputs.capture_environment.clone(),
            inference_parameters: inputs.inference_parameters.clone(),
            audio_fingerprint,
        },
        amends: inputs.amends.clone(),
    };

    let manifest_bytes = canonicalize(&manifest)?;
    let signature = signer.sign(&manifest_bytes)?;
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&signature);
    let signature_doc = SignatureDocument {
        algorithm: signer_algorithm.as_str().to_string(),
        key_id: inputs.signer_key_id.clone(),
        signature_b64,
        signed_payload: paths::MANIFEST.to_string(),
        canonicalization: "rfc8785".to_string(),
    };
    let signature_bytes = canonicalize(&signature_doc)?;

    // Public key is intentionally NOT shipped as a standalone bundle entry.
    // The signed manifest's `signer.public_key_pem` is what verifiers consume,
    // so a standalone `public_key.pem` would be a redundant unsigned file the
    // signature does not cover. Shipping only the signed copy eliminates the
    // class of attacks where a reviewer extracts the standalone file and
    // mistakes a substituted key for "the signer's key."
    let mut entries: Vec<ZipEntry> = Vec::with_capacity(3 + image_blobs.len());
    entries.push(ZipEntry {
        path: paths::MANIFEST.to_string(),
        data: manifest_bytes,
    });
    entries.push(ZipEntry {
        path: paths::SIGNATURE.to_string(),
        data: signature_bytes,
    });
    entries.push(ZipEntry {
        path: paths::AUDIO.to_string(),
        data: audio_bytes,
    });
    for (path, bytes, _) in image_blobs {
        entries.push(ZipEntry { path, data: bytes });
    }
    entries.push(ZipEntry {
        path: paths::REASONING.to_string(),
        data: inputs.reasoning_trace_bytes.clone(),
    });

    write_bundle(out_path, &entries)?;
    Ok(bundle_id)
}

fn image_extension(path: &Path) -> Result<String, WitnessCoreError> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .ok_or_else(|| WitnessCoreError::UnsupportedImage {
            path: path.to_path_buf(),
            detail: "missing file extension; expected jpg, jpeg, or png".to_string(),
        })?;
    match ext.as_str() {
        "jpg" | "jpeg" => Ok("jpg".to_string()),
        "png" => Ok("png".to_string()),
        other => Err(WitnessCoreError::UnsupportedImage {
            path: path.to_path_buf(),
            detail: format!("unsupported extension {other}; expected jpg, jpeg, or png"),
        }),
    }
}

fn media_type_for(in_zip_path: &str) -> String {
    if in_zip_path.ends_with(".png") {
        "image/png".to_string()
    } else {
        "image/jpeg".to_string()
    }
}

/// Convenience: hash the file at `path` so callers can compose their own
/// asset entries.
pub fn hash_path(path: &Path) -> Result<String, WitnessCoreError> {
    hash_file_hex(path)
}

/// Drop the attestation blob when the wire manifest is v1.
///
/// v1 manifests forbid `signer.attestation` (the verifier rejects v1
/// bundles that carry it). Software-only Ed25519 signers default to None,
/// but a defensive guard here keeps a future BundleSigner impl from
/// silently producing a malformed bundle by attaching attestation to an
/// Ed25519 (= v1) signer.
fn attestation_for_version(
    manifest_version: u32,
    candidate: Option<SignerAttestation>,
) -> Option<SignerAttestation> {
    if manifest_version >= 2 {
        candidate
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_attestation() -> SignerAttestation {
        SignerAttestation {
            format: "apple-sep-v1".to_string(),
            payload_b64: "AAECAwQF".to_string(),
            certificate_chain_b64: None,
        }
    }

    #[test]
    fn attestation_passes_through_on_v2() {
        let kept = attestation_for_version(2, Some(fixture_attestation()));
        assert_eq!(kept, Some(fixture_attestation()));
    }

    #[test]
    fn attestation_is_dropped_on_v1() {
        let dropped = attestation_for_version(1, Some(fixture_attestation()));
        assert!(
            dropped.is_none(),
            "v1 manifests forbid signer.attestation; the guard must strip it even \
             if a future provider supplies one"
        );
    }

    #[test]
    fn missing_attestation_stays_missing_on_v2() {
        assert!(attestation_for_version(2, None).is_none());
    }
}
