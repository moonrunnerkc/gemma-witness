//! `seal_bundle` Tauri command.

use std::path::PathBuf;

use serde::Serialize;
use tauri::State;
use witness_core::bundle_builder::{build_and_seal_bundle, BundleInputs, BundleSigner};
use witness_core::keystore::{load_or_create_device_key, sign_with_device_key};
use witness_core::manifest::{
    CaptureEnvironment, ConsistencyLabel, ConsistencyVerdict, ModelFingerprint,
};
use witness_core::WitnessCoreError;

use crate::error::AppError;
use crate::state::SharedState;

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedBundle {
    pub bundle_id: String,
    pub path: String,
}

struct KeystoreSigner;

impl BundleSigner for KeystoreSigner {
    fn sign(&self, payload: &[u8]) -> Result<[u8; 64], WitnessCoreError> {
        let signature = sign_with_device_key(payload)?;
        Ok(signature.to_bytes())
    }
}

#[tauri::command]
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

    let device_key = load_or_create_device_key()?;
    let fingerprint = load_model_fingerprint()?;

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
    };

    let bundles_dir = data_dir.join("bundles");
    std::fs::create_dir_all(&bundles_dir).map_err(|err| AppError::Io {
        path: bundles_dir.display().to_string(),
        detail: err.to_string(),
    })?;
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let out_path: PathBuf = bundles_dir.join(format!("incident-{stamp}.witness"));

    let bundle_id = build_and_seal_bundle(&inputs, &KeystoreSigner, &out_path)?;

    Ok(SealedBundle {
        bundle_id,
        path: out_path.display().to_string(),
    })
}

fn load_model_fingerprint() -> Result<ModelFingerprint, AppError> {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../../inference/mlx-sidecar/model-fingerprint.json");
    let raw = std::fs::read_to_string(&p).map_err(|err| AppError::Io {
        path: p.display().to_string(),
        detail: format!("read model-fingerprint.json: {err}"),
    })?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).map_err(|err| AppError::State {
        detail: format!("parse model-fingerprint.json: {err}"),
    })?;
    let model_id = parsed["model_id"]
        .as_str()
        .ok_or_else(|| AppError::State {
            detail: "model-fingerprint.json missing model_id".to_string(),
        })?
        .to_string();
    let revision = parsed["revision"].as_str().unwrap_or("main").to_string();
    let sha256 = parsed["files"][0]["sha256"]
        .as_str()
        .ok_or_else(|| AppError::State {
            detail: "model-fingerprint.json missing files[0].sha256".to_string(),
        })?
        .to_string();
    Ok(ModelFingerprint {
        model_id,
        revision,
        sha256,
    })
}

fn hostname_opt() -> Option<String> {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
}
