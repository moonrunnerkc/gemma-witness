//! Device key initialization and per-capture lifecycle commands.

use rand::RngCore;
use tauri::{AppHandle, Manager, State};
use witness_core::keystore::load_or_create_device_key;
use witness_inference::SIDECAR_TOKEN_ENV;

use crate::error::AppError;
use crate::state::SharedState;

/// Ensure a device key exists in the OS keychain. Returns the lowercase
/// hex SHA-256 of the raw public key (the key id used inside manifests).
#[tauri::command]
#[specta::specta]
pub async fn initialize_device(
    app: AppHandle,
    state: State<'_, SharedState>,
) -> Result<String, AppError> {
    let data_dir = app
        .path()
        .app_local_data_dir()
        .map_err(|err| AppError::Io {
            path: "(app_local_data_dir)".to_string(),
            detail: err.to_string(),
        })?;
    std::fs::create_dir_all(&data_dir)
        .map_err(|err| AppError::io_relative(&data_dir, &data_dir, err.to_string()))?;

    let key = load_or_create_device_key()?;

    // We deliberately do not write a standalone `device-public-key.pem` to
    // disk anymore. The signed manifest.signer.public_key_pem is the only
    // authoritative copy of the public key; a standalone file invited the
    // "extract the file to publish the signer's key" mistake closed under
    // audit finding C-5.

    let token = std::env::var(SIDECAR_TOKEN_ENV)
        .ok()
        .filter(|s| !s.is_empty());
    let token = match token {
        Some(t) => t,
        None => {
            // Issue a fresh per-launch token and write it into our own env
            // for downstream witness-inference calls. The sidecar process
            // must be started with the same value via its own env var; this
            // is documented in inference/mlx-sidecar/README.md.
            let mut buf = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut buf);
            let issued = hex::encode(buf);
            std::env::set_var(SIDECAR_TOKEN_ENV, &issued);
            tracing::info!(
                "issued per-launch sidecar token; start the sidecar with GW_SIDECAR_TOKEN={} \
                 (the audit recommends spawning the sidecar from the capture app to avoid this manual step)",
                issued
            );
            issued
        }
    };

    {
        let mut guard = state.lock().await;
        guard.sidecar_token = Some(token);
    }

    Ok(key.key_id)
}

/// Wipe per-capture working files: the audio recording, the reasoning
/// trace, the intermediate bundle (if any), and the staged images.
/// Closes audit finding T-6.
///
/// Idempotent: missing directories are not an error.
#[tauri::command]
#[specta::specta]
pub async fn discard_capture_cmd(
    app: AppHandle,
    state: State<'_, SharedState>,
) -> Result<(), AppError> {
    let data_dir = app
        .path()
        .app_local_data_dir()
        .map_err(|err| AppError::Io {
            path: "(app_local_data_dir)".to_string(),
            detail: err.to_string(),
        })?;

    {
        let mut guard = state.lock().await;
        if guard.recording.is_some() {
            return Err(AppError::State {
                detail: "a recording is in progress; stop it before discarding".to_string(),
            });
        }
        guard.captured_audio = None;
        guard.picked_images.clear();
        guard.last_pipeline = None;
        guard.reasoning_path = None;
    }

    for sub in ["recordings", "reasoning", "staged-images"] {
        let dir = data_dir.join(sub);
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {
                tracing::info!(path = ?dir, "discarded working directory");
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                tracing::error!(path = ?dir, %err, "discard failed");
                return Err(AppError::io_relative(
                    &data_dir,
                    &dir,
                    format!("discard: {err}"),
                ));
            }
        }
    }
    Ok(())
}
