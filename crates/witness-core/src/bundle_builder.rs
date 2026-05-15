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
    ModelFingerprint, ReasoningTrace, SignatureDocument, SignerInfo, MANIFEST_VERSION,
};
use crate::{IncidentReport, InferenceParameters};

/// In-zip layout constants.
pub mod paths {
    pub const MANIFEST: &str = "manifest.json";
    pub const SIGNATURE: &str = "signature.json";
    pub const PUBLIC_KEY_PEM: &str = "public_key.pem";
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
}

/// A signer is anything that can produce a 64-byte Ed25519 signature over a
/// payload. The capture app passes the keystore-backed implementation; tests
/// can pass an in-memory signing key.
pub trait BundleSigner {
    fn sign(&self, payload: &[u8]) -> Result<[u8; 64], WitnessCoreError>;
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

    let mut image_blobs: Vec<(String, Vec<u8>, String)> =
        Vec::with_capacity(inputs.image_paths.len());
    for (i, image_path) in inputs.image_paths.iter().enumerate() {
        let extension = image_extension(image_path)?;
        let bytes = std::fs::read(image_path).map_err(|source| WitnessCoreError::AssetRead {
            path: image_path.clone(),
            source,
        })?;
        let hash = hash_bytes_hex(&bytes);
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
    let manifest = Manifest {
        manifest_version: MANIFEST_VERSION,
        bundle_id: bundle_id.clone(),
        created_at: Utc::now().to_rfc3339(),
        signer: SignerInfo {
            algorithm: "ed25519".to_string(),
            public_key_pem: inputs.signer_public_key_pem.clone(),
            key_id: inputs.signer_key_id.clone(),
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
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature);
    let signature_doc = SignatureDocument {
        algorithm: "ed25519".to_string(),
        key_id: inputs.signer_key_id.clone(),
        signature_b64,
        signed_payload: paths::MANIFEST.to_string(),
        canonicalization: "rfc8785".to_string(),
    };
    let signature_bytes = canonicalize(&signature_doc)?;

    let mut entries: Vec<ZipEntry> = Vec::with_capacity(4 + image_blobs.len());
    entries.push(ZipEntry {
        path: paths::MANIFEST.to_string(),
        data: manifest_bytes,
    });
    entries.push(ZipEntry {
        path: paths::SIGNATURE.to_string(),
        data: signature_bytes,
    });
    entries.push(ZipEntry {
        path: paths::PUBLIC_KEY_PEM.to_string(),
        data: inputs.signer_public_key_pem.as_bytes().to_vec(),
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
