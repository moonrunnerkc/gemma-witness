//! `seal_bundle` Tauri command.

use std::path::PathBuf;

use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager, State};
use witness_core::bundle_builder::{build_and_seal_bundle, BundleInputs, BundleSigner};
use witness_core::key_provider::{KeyProvider, SigningAlgorithm, SoftwareEd25519Provider};
use witness_core::manifest::{
    CaptureEnvironment, ConsistencyLabel, ConsistencyVerdict, ModelFingerprint,
};
use witness_core::WitnessCoreError;
use witness_fingerprints::FingerprintError;
use witness_inference::{
    fetch_active_model_id_default, inference_parameters_snapshot, DEFAULT_ENDPOINT,
};

use crate::error::AppError;
use crate::state::SharedState;

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const MODEL_SAFETENSORS_ENV: &str = "WITNESS_MODEL_SAFETENSORS_PATH";

#[derive(Debug, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct SealedBundle {
    pub bundle_id: String,
    pub signer_key_id: String,
    pub path: String,
    /// `"ed25519"` for software-only seals, `"ecdsa-p256"` when the bundle
    /// was sealed by a hardware-backed provider (Secure Enclave today;
    /// TPM/NCrypt later). The UI uses this to decide whether to display
    /// the "software-only seal" warning banner.
    pub signer_algorithm: String,
    /// True when the capture app fell back to a software signer because
    /// the platform's hardware backend was unavailable. The UI raises a
    /// banner so the user knows the bundle does not carry hardware
    /// provenance. Always true on Linux and Windows today.
    pub software_fallback: bool,
    /// Human-readable explanation of which backend produced the seal and,
    /// when `software_fallback == true`, what went wrong with the hardware
    /// attempt. Echoed verbatim into the UI; do not localize.
    pub signer_backend_note: String,
}

#[tauri::command]
#[specta::specta]
pub async fn seal_bundle_cmd(
    app: AppHandle,
    state: State<'_, SharedState>,
) -> Result<SealedBundle, AppError> {
    let data_dir = derive_data_dir(&app)?;

    // Re-entrancy guard (audit T-9).
    let (audio_path, image_paths, snapshot) = {
        let mut guard = state.lock().await;
        if guard.running_seal {
            return Err(AppError::AlreadyInProgress {
                operation: "seal".to_string(),
            });
        }
        let audio = guard
            .captured_audio
            .as_ref()
            .ok_or(AppError::NoCapturedAudio)?
            .path
            .clone();
        let images: Vec<PathBuf> = guard
            .picked_images
            .iter()
            .map(|i| i.staged_path.clone())
            .collect();
        let snap = guard.last_pipeline.clone().ok_or_else(|| AppError::State {
            detail: "no inference pipeline output staged; run inference before sealing".to_string(),
        })?;
        guard.running_seal = true;
        (audio, images, snap)
    };

    let result = seal_inner(&data_dir, audio_path, image_paths, snapshot).await;

    {
        let mut guard = state.lock().await;
        guard.running_seal = false;
    }
    result
}

async fn seal_inner(
    data_dir: &std::path::Path,
    audio_path: PathBuf,
    image_paths: Vec<PathBuf>,
    snapshot: crate::state::PipelineSnapshot,
) -> Result<SealedBundle, AppError> {
    let SealSigner {
        public_key_pem,
        key_id: device_key_id,
        algorithm,
        backend_note,
        software_fallback,
        sign_fn,
        attestation_fn,
    } = choose_signer()?;
    let signer_key_id = device_key_id.clone();
    let fingerprint = resolve_active_model_fingerprint().await?;

    verify_live_model_matches_registry(&fingerprint)?;

    let verdict_label = match snapshot.consistency_verdict.as_str() {
        "consistent" => ConsistencyLabel::Consistent,
        _ => ConsistencyLabel::Inconsistent,
    };

    let pinned_audio_sha256 = snapshot.pinned_audio_sha256.clone();
    let pinned_image_sha256s = snapshot.pinned_image_sha256s.clone();
    if pinned_image_sha256s.len() != image_paths.len() {
        return Err(AppError::State {
            detail: format!(
                "inference produced {} image hashes but {} images are staged. re-run inference after picking images.",
                pinned_image_sha256s.len(),
                image_paths.len()
            ),
        });
    }

    let inputs = BundleInputs {
        audio_path,
        image_paths,
        reasoning_trace_bytes: snapshot.reasoning_trace.into_bytes(),
        incident_report: snapshot.report,
        consistency: ConsistencyVerdict {
            verdict: verdict_label,
            summary: Some(snapshot.consistency_reason),
        },
        model_fingerprint: fingerprint,
        capture_environment: CaptureEnvironment {
            os: std::env::consts::OS.to_string(),
            hostname: hostname_opt(),
            app_version: APP_VERSION.to_string(),
            captured_at: chrono::Utc::now().to_rfc3339(),
        },
        signer_public_key_pem: public_key_pem,
        signer_key_id: device_key_id,
        inference_parameters: Some(inference_parameters_snapshot()),
        amends: None,
        pinned_audio_sha256: Some(pinned_audio_sha256),
        pinned_image_sha256s: Some(pinned_image_sha256s),
    };

    let bundles_dir = data_dir.join("bundles");
    std::fs::create_dir_all(&bundles_dir).map_err(|err| {
        tracing::error!(path = ?bundles_dir, %err, "create bundles dir");
        AppError::io_relative(data_dir, &bundles_dir, err.to_string())
    })?;
    let bundle_uuid = uuid::Uuid::new_v4().to_string();
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let mut out_path: PathBuf = bundles_dir.join(format!("incident-{stamp}.witness"));
    // T-11: never truncate an existing bundle. Take a UUID suffix when
    // a same-second seal would collide.
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&out_path)
    {
        Ok(_) => {
            // We just opened a placeholder; drop the handle so build_and_seal_bundle can
            // recreate the file via its zip writer. The placeholder reserves the path
            // against a parallel seal racing for the same filename.
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            out_path = bundles_dir.join(format!("incident-{stamp}-{bundle_uuid}.witness"));
        }
        Err(err) => {
            tracing::error!(path = ?out_path, %err, "create_new bundle output");
            return Err(AppError::io_relative(
                data_dir,
                &out_path,
                format!("create_new: {err}"),
            ));
        }
    }

    let signer = ChosenSigner {
        sign_fn,
        attestation_fn,
        algorithm,
    };
    let bundle_id = build_and_seal_bundle(&inputs, &signer, &out_path)?;

    Ok(SealedBundle {
        bundle_id,
        signer_key_id,
        path: out_path.display().to_string(),
        signer_algorithm: algorithm.as_str().to_string(),
        software_fallback,
        signer_backend_note: backend_note,
    })
}

/// Output of [`choose_signer`]: a closure-based [`BundleSigner`] plus the
/// public-key surface and human-readable backend description the seal
/// path forwards into [`SealedBundle`].
///
/// We deliberately avoid a `Box<dyn KeyProvider>` here so the trait does
/// not need to grow `Send + Sync` bounds beyond what's already present;
/// the closure pair captures whichever concrete provider we picked at
/// runtime and keeps the seal path platform-agnostic.
struct SealSigner {
    public_key_pem: String,
    key_id: String,
    algorithm: SigningAlgorithm,
    backend_note: String,
    software_fallback: bool,
    sign_fn: SignFn,
    attestation_fn: AttestationFn,
}

type SignFn = Box<dyn Fn(&[u8]) -> Result<Vec<u8>, WitnessCoreError> + Send + Sync>;
type AttestationFn =
    Box<dyn Fn() -> Option<witness_core::manifest::SignerAttestation> + Send + Sync>;

struct ChosenSigner {
    sign_fn: SignFn,
    attestation_fn: AttestationFn,
    algorithm: SigningAlgorithm,
}

impl BundleSigner for ChosenSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, WitnessCoreError> {
        (self.sign_fn)(payload)
    }
    fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }
    fn attestation(&self) -> Option<witness_core::manifest::SignerAttestation> {
        (self.attestation_fn)()
    }
}

/// Pick a signing backend in preference order: hardware-backed when the
/// target supports it, software fallback otherwise. The first successful
/// load wins; a hardware failure falls through to software with a warning.
#[cfg(target_os = "macos")]
fn choose_signer() -> Result<SealSigner, AppError> {
    use witness_core::secure_enclave::SecureEnclaveProvider;
    let provider = std::sync::Arc::new(SecureEnclaveProvider::new());
    match provider.load_or_create_public() {
        Ok(handle) => {
            let provider_for_sign = std::sync::Arc::clone(&provider);
            let provider_for_att = std::sync::Arc::clone(&provider);
            Ok(SealSigner {
                public_key_pem: handle.public_key_pem,
                key_id: handle.key_id,
                algorithm: SigningAlgorithm::EcdsaP256,
                backend_note: "sealed by the Apple Secure Enclave (hardware-backed ECDSA P-256)."
                    .to_string(),
                software_fallback: false,
                sign_fn: Box::new(move |payload| provider_for_sign.sign(payload)),
                attestation_fn: Box::new(move || provider_for_att.attestation()),
            })
        }
        Err(err) => {
            tracing::warn!(
                %err,
                "Secure Enclave key generation failed; falling back to software signing"
            );
            Ok(software_signer(format!(
                "fell back to a software Ed25519 key because the Secure Enclave was \
                 unavailable: {err}. attempted: ECDSA P-256 in SEP."
            )))
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn choose_signer() -> Result<SealSigner, AppError> {
    Ok(software_signer(
        "sealed by the software Ed25519 keychain key. hardware-backed signing is not \
         yet implemented for this platform; bundles produced here do not carry \
         cryptographic proof that they were signed on a specific device."
            .to_string(),
    ))
}

fn software_signer(backend_note: String) -> SealSigner {
    let provider = std::sync::Arc::new(SoftwareEd25519Provider::new());
    // load_or_create_public is fallible, but the prior shipping seal path
    // panicked on failure via `?` at the call site; we surface the same
    // behaviour but wrap it in the chosen-signer envelope so the seal
    // path stays uniform.
    let handle = match provider.load_or_create_public() {
        Ok(h) => h,
        Err(err) => {
            // Caller's `?` will lift this through Into<AppError>. We return a
            // sentinel so the type aligns; the seal path errors out before
            // ever calling sign_fn.
            return SealSigner {
                public_key_pem: String::new(),
                key_id: String::new(),
                algorithm: SigningAlgorithm::Ed25519,
                backend_note: format!("software key load failed: {err}"),
                software_fallback: true,
                sign_fn: Box::new(move |_| {
                    Err(WitnessCoreError::Keyring {
                        detail: "software key never loaded; cannot sign".to_string(),
                    })
                }),
                attestation_fn: Box::new(|| None),
            };
        }
    };
    let provider_for_sign = std::sync::Arc::clone(&provider);
    SealSigner {
        public_key_pem: handle.public_key_pem,
        key_id: handle.key_id,
        algorithm: SigningAlgorithm::Ed25519,
        backend_note,
        software_fallback: true,
        sign_fn: Box::new(move |payload| provider_for_sign.sign(payload)),
        attestation_fn: Box::new(|| None),
    }
}

/// Reveal a sealed bundle in the host file manager.
#[tauri::command]
#[specta::specta]
pub async fn reveal_bundle_cmd(app: AppHandle, path: String) -> Result<(), AppError> {
    let data_dir = derive_data_dir(&app)?;
    let bundles_dir = data_dir.join("bundles");
    let requested = std::path::PathBuf::from(path);
    let canonical_requested = requested.canonicalize().map_err(|err| AppError::Io {
        path: requested.display().to_string(),
        detail: format!("bundle path does not exist: {err}"),
    })?;
    let canonical_bundles = bundles_dir.canonicalize().map_err(|err| AppError::Io {
        path: bundles_dir.display().to_string(),
        detail: format!("bundles directory does not exist: {err}"),
    })?;
    if !canonical_requested.starts_with(&canonical_bundles)
        || canonical_requested.extension().and_then(|s| s.to_str()) != Some("witness")
    {
        return Err(AppError::State {
            detail: "refusing to reveal a path outside the sealed bundle directory".to_string(),
        });
    }

    reveal_path(&canonical_requested)
}

#[cfg(target_os = "macos")]
fn reveal_path(path: &std::path::Path) -> Result<(), AppError> {
    let status = std::process::Command::new("open")
        .arg("-R")
        .arg(path)
        .status()
        .map_err(|err| AppError::State {
            detail: format!("could not launch Finder: {err}"),
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(AppError::State {
            detail: format!("Finder reveal exited with status {status}"),
        })
    }
}

#[cfg(target_os = "windows")]
fn reveal_path(path: &std::path::Path) -> Result<(), AppError> {
    let status = std::process::Command::new("explorer")
        .arg(format!("/select,{}", path.display()))
        .status()
        .map_err(|err| AppError::State {
            detail: format!("could not launch Explorer: {err}"),
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(AppError::State {
            detail: format!("Explorer reveal exited with status {status}"),
        })
    }
}

#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
fn reveal_path(path: &std::path::Path) -> Result<(), AppError> {
    let dir = path.parent().ok_or_else(|| AppError::State {
        detail: "bundle path has no parent directory".to_string(),
    })?;
    let status = std::process::Command::new("xdg-open")
        .arg(dir)
        .status()
        .map_err(|err| AppError::State {
            detail: format!("could not launch file manager: {err}"),
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(AppError::State {
            detail: format!("file manager reveal exited with status {status}"),
        })
    }
}

/// Hash `model.safetensors` at seal time and compare against the registry's
/// pinned SHA-256. The path is taken from
/// [`WITNESS_MODEL_SAFETENSORS_PATH`] which the operator points at the
/// sidecar's loaded weights file. Closes audit finding C-13: previously the
/// seal recorded whatever the registry said the hash was, never the live
/// model's actual bytes.
fn verify_live_model_matches_registry(fp: &ModelFingerprint) -> Result<(), AppError> {
    let path = match std::env::var(MODEL_SAFETENSORS_ENV) {
        Ok(p) if !p.is_empty() => std::path::PathBuf::from(p),
        _ => {
            return Err(AppError::State {
                detail: format!(
                    "{MODEL_SAFETENSORS_ENV} is not set. point it at the model.safetensors file the running sidecar loaded so seal can confirm the live model matches the pinned fingerprint registry entry. see README \"trust model\" section."
                ),
            });
        }
    };
    if model_path_claims_expected_hash(&path, &fp.sha256) {
        tracing::info!(
            path = ?path,
            sha256 = %fp.sha256,
            "accepted Hugging Face content-addressed model path without re-hashing full weights"
        );
        return Ok(());
    }

    let mut file = std::fs::File::open(&path).map_err(|err| {
        tracing::error!(?path, %err, "open model.safetensors for seal-time hash");
        AppError::State {
            detail: format!(
                "could not open model.safetensors at {} (set via {MODEL_SAFETENSORS_ENV}): {err}",
                path.display()
            ),
        }
    })?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).map_err(|err| AppError::State {
        detail: format!(
            "could not read model.safetensors at {} for hashing: {err}",
            path.display()
        ),
    })?;
    let observed = hex::encode(hasher.finalize());
    if observed != fp.sha256 {
        return Err(AppError::State {
            detail: format!(
                "live model.safetensors at {} hashes to {} but the registry pins {} for {}@{}. \
                 refusing to seal: the running sidecar is not the audited model. \
                 confirm the sidecar is serving the pinned revision and re-run seal.",
                path.display(),
                observed,
                fp.sha256,
                fp.model_id,
                fp.revision
            ),
        });
    }
    Ok(())
}

/// Hugging Face snapshot files are symlinks into `hub/.../blobs/<sha256>`.
/// When the operator points `WITNESS_MODEL_SAFETENSORS_PATH` at that normal
/// snapshot path, the symlink target is the content-addressed blob name. Use
/// that O(1) identity check before falling back to hashing the multi-GB model
/// file, which is painfully slow in unoptimized Tauri dev builds.
fn model_path_claims_expected_hash(path: &std::path::Path, expected_sha256: &str) -> bool {
    if !is_lower_hex_sha256(expected_sha256) {
        return false;
    }
    if path_file_name_eq(path, expected_sha256) {
        return true;
    }
    match std::fs::read_link(path) {
        Ok(target) => path_file_name_eq(&target, expected_sha256),
        Err(_) => false,
    }
}

fn path_file_name_eq(path: &std::path::Path, expected: &str) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == expected)
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Ask the live sidecar which model is loaded, then resolve the matching
/// fingerprint from the embedded registry. Replaces the previous hardcoded
/// MLX path, which produced incorrect fingerprints on Linux/Windows and
/// would fail at runtime in a shipped binary because the source-tree path
/// it depended on does not exist on user machines.
async fn resolve_active_model_fingerprint() -> Result<ModelFingerprint, AppError> {
    let endpoint =
        std::env::var("GW_SIDECAR_ENDPOINT").unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string());
    let model_id = fetch_active_model_id_default(&endpoint)
        .await
        .map_err(|err| AppError::Inference {
            detail: format!(
                "could not query live sidecar at {endpoint} for active model: {err}. start a sidecar before sealing"
            ),
        })?;
    let revision = revision_for_model_id(&model_id);

    witness_fingerprints::lookup(&model_id, revision).map_err(map_fingerprint_error)
}

/// Map well-known model_ids to the pinned revision. A model_id without a
/// pinned revision falls back to `main`, which matches the index format and
/// surfaces a clear "unseeded" error if no entry has been recorded yet.
fn revision_for_model_id(model_id: &str) -> &'static str {
    match model_id {
        "mlx-community/gemma-4-e4b-it-4bit" => "cc3b666c01c20395e0dcebd53854504c7d9821f9",
        _ => "main",
    }
}

fn map_fingerprint_error(err: FingerprintError) -> AppError {
    match err {
        FingerprintError::Unknown { model_id, revision } => AppError::State {
            detail: format!(
                "the running sidecar is serving {model_id}@{revision}, which is not in the pinned fingerprint registry. add it via tools/seed-fingerprints and rebuild before sealing"
            ),
        },
        FingerprintError::UnseededEntry { model_id, revision } => AppError::State {
            detail: format!(
                "fingerprint registry has an entry for {model_id}@{revision} but its sha256 is null. run tools/seed-fingerprints on a host with the model cached before sealing"
            ),
        },
        FingerprintError::IndexSchemaMismatch { found, expected } => AppError::State {
            detail: format!(
                "fingerprint registry schema mismatch: embedded index reports v{found}, this build expected v{expected}. rebuild the capture app"
            ),
        },
        FingerprintError::Empty => AppError::State {
            detail: "fingerprint registry is empty. rebuild after running tools/seed-fingerprints"
                .to_string(),
        },
        FingerprintError::Corrupt { detail } => AppError::State {
            detail: format!("fingerprint registry corrupt: {detail}"),
        },
    }
}

fn hostname_opt() -> Option<String> {
    let raw = gethostname::gethostname();
    let s = raw.to_string_lossy().trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn derive_data_dir(app: &AppHandle) -> Result<std::path::PathBuf, AppError> {
    app.path().app_local_data_dir().map_err(|err| AppError::Io {
        path: "(app_local_data_dir)".to_string(),
        detail: err.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "339409bd18494955556e1fde6ccc15faaa9f707b911b74791fe290b9d722beed";

    #[test]
    fn direct_blob_path_claims_expected_hash() {
        let path = std::path::PathBuf::from(format!("/tmp/blobs/{SHA}"));
        assert!(model_path_claims_expected_hash(&path, SHA));
    }

    #[test]
    fn non_hash_path_does_not_claim_expected_hash() {
        let path = std::path::PathBuf::from("/tmp/model.safetensors");
        assert!(!model_path_claims_expected_hash(&path, SHA));
    }

    #[test]
    fn rejects_uppercase_or_short_expected_hashes() {
        let upper = SHA.to_ascii_uppercase();
        let path = std::path::PathBuf::from(format!("/tmp/blobs/{upper}"));
        assert!(!model_path_claims_expected_hash(&path, &upper));
        assert!(!model_path_claims_expected_hash(&path, "abc"));
    }
}
