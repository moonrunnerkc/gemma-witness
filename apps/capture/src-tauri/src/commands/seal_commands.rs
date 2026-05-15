//! `seal_bundle` Tauri command.

use std::path::PathBuf;

use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager, State};
use witness_core::bundle_builder::{build_and_seal_bundle, BundleInputs, BundleSigner};
use witness_core::key_provider::{KeyProvider, SoftwareEd25519Provider};
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
    pub path: String,
}

/// Adapter from the abstract [`KeyProvider`] trait to the bundle builder's
/// fixed 64-byte signature contract. Today only Ed25519 implementations
/// flow through; when a P-256 hardware backend lands, the builder will gain
/// a variant for variable-length signatures and this adapter will pick the
/// right path based on `provider.algorithm()`.
struct KeyProviderSigner<P> {
    provider: P,
}

impl<P: KeyProvider> BundleSigner for KeyProviderSigner<P> {
    fn sign(&self, payload: &[u8]) -> Result<[u8; 64], WitnessCoreError> {
        let raw = self.provider.sign(payload)?;
        if raw.len() != 64 {
            return Err(WitnessCoreError::Keyring {
                detail: format!(
                    "key provider returned a {}-byte signature; the v1 manifest requires 64 (Ed25519). \
                     a future provider may use a different algorithm; bump manifest_version when wiring it up.",
                    raw.len()
                ),
            });
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&raw);
        Ok(sig)
    }
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
    let key_provider = SoftwareEd25519Provider::new();
    let device_key = key_provider.load_or_create_public()?;
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
        signer_public_key_pem: device_key.public_key_pem,
        signer_key_id: device_key.key_id,
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

    let signer = KeyProviderSigner {
        provider: key_provider,
    };
    let bundle_id = build_and_seal_bundle(&inputs, &signer, &out_path)?;

    Ok(SealedBundle {
        bundle_id,
        path: crate::error::relativize_for_frontend(data_dir, &out_path),
    })
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
