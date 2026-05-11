//! Device key initialization command.

use tauri::{AppHandle, Manager, State};
use witness_core::keystore::load_or_create_device_key;

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
    std::fs::create_dir_all(&data_dir).map_err(|err| AppError::Io {
        path: data_dir.display().to_string(),
        detail: err.to_string(),
    })?;

    let key = load_or_create_device_key()?;

    let pem_path = data_dir.join("device-public-key.pem");
    std::fs::write(&pem_path, key.public_key_pem.as_bytes()).map_err(|err| AppError::Io {
        path: pem_path.display().to_string(),
        detail: err.to_string(),
    })?;

    {
        let mut guard = state.lock().await;
        guard.data_dir = Some(data_dir);
    }

    Ok(key.key_id)
}
