//! `seal_bundle` Tauri command.

use std::path::PathBuf;

use serde::Serialize;
use tauri::State;
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
pub async fn seal_bundle_cmd(state: State<'_, SharedState>) -> Result<SealedBundle, AppError> {
    let (audio_path, image_paths, snapshot, data_dir) = {
        let guard = state.lock().await;
        let audio = guard
            .captured_audio
            .as_ref()
            .ok_or(AppError::NoCapturedAudio)?
            .path
            .clone();
        let images = guard.picked_images.clone();
        let snap = guard.last_pipeline.clone().ok_or_else(|| AppError::State {
            detail: "no inference pipeline output staged; run inference before sealing".to_string(),
        })?;
        let data_dir = guard.data_dir.clone().ok_or_else(|| AppError::State {
            detail: "app_local_data_dir was not initialized; call initialize_device first"
                .to_string(),
        })?;
        (audio, images, snap, data_dir)
    };

    let key_provider = SoftwareEd25519Provider::new();
    let device_key = key_provider.load_or_create_public()?;
    let fingerprint = resolve_active_model_fingerprint().await?;

    let verdict_label = match snapshot.consistency_verdict.as_str() {
        "consistent" => ConsistencyLabel::Consistent,
        _ => ConsistencyLabel::Inconsistent,
    };

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
        // Amendment chains are part of the format. The UI does not yet
        // surface a way to issue one, so production seals always emit
        // non-amending bundles. A future capture flow can populate this
        // field by extending the seal command's inputs.
        amends: None,
    };

    let bundles_dir = data_dir.join("bundles");
    std::fs::create_dir_all(&bundles_dir).map_err(|err| AppError::Io {
        path: bundles_dir.display().to_string(),
        detail: err.to_string(),
    })?;
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let out_path: PathBuf = bundles_dir.join(format!("incident-{stamp}.witness"));

    let signer = KeyProviderSigner {
        provider: key_provider,
    };
    let bundle_id = build_and_seal_bundle(&inputs, &signer, &out_path)?;

    Ok(SealedBundle {
        bundle_id,
        path: out_path.display().to_string(),
    })
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
