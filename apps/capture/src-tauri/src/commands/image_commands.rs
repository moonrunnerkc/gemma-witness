//! `pick_images` Tauri command.

use std::path::PathBuf;

use serde::Serialize;
use tauri::State;
use tauri_plugin_dialog::DialogExt;

use crate::error::AppError;
use crate::state::SharedState;

/// Image extensions accepted by the capture flow.
const ALLOWED_EXTENSIONS: &[&str] = &["jpg", "jpeg", "png"];
/// Maximum per-file size, in bytes.
const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;
/// Maximum number of images per call.
const MAX_FILES: usize = 4;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PickedImages {
    pub paths: Vec<String>,
    pub count: usize,
}

#[tauri::command]
pub async fn pick_images_cmd(
    app: tauri::AppHandle,
    state: State<'_, SharedState>,
) -> Result<PickedImages, AppError> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .add_filter("Images", ALLOWED_EXTENSIONS)
        .pick_files(move |paths| {
            let _ = tx.send(paths);
        });

    let selection = rx.await.map_err(|err| AppError::ImageRejected {
        detail: format!("dialog channel closed: {err}"),
    })?;

    let raw_paths = selection.unwrap_or_default();
    if raw_paths.is_empty() {
        return Ok(PickedImages {
            paths: Vec::new(),
            count: 0,
        });
    }
    if raw_paths.len() > MAX_FILES {
        return Err(AppError::ImageRejected {
            detail: format!(
                "selected {} files but the limit is {MAX_FILES}",
                raw_paths.len()
            ),
        });
    }

    let mut accepted: Vec<PathBuf> = Vec::with_capacity(raw_paths.len());
    for entry in raw_paths {
        let path = entry.into_path().map_err(|err| AppError::ImageRejected {
            detail: format!("could not resolve dialog path: {err}"),
        })?;
        validate(&path)?;
        accepted.push(path);
    }

    let display_paths: Vec<String> = accepted.iter().map(|p| p.display().to_string()).collect();

    {
        let mut guard = state.lock().await;
        guard.picked_images = accepted;
    }

    Ok(PickedImages {
        count: display_paths.len(),
        paths: display_paths,
    })
}

fn validate(path: &std::path::Path) -> Result<(), AppError> {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .ok_or_else(|| AppError::ImageRejected {
            detail: format!("file {} has no extension", path.display()),
        })?;
    if !ALLOWED_EXTENSIONS.contains(&ext.as_str()) {
        return Err(AppError::ImageRejected {
            detail: format!(
                "file {} has extension {ext}; only jpg, jpeg, png are accepted",
                path.display()
            ),
        });
    }
    let metadata = std::fs::metadata(path).map_err(|err| AppError::Io {
        path: path.display().to_string(),
        detail: err.to_string(),
    })?;
    if metadata.len() > MAX_FILE_BYTES {
        return Err(AppError::ImageRejected {
            detail: format!(
                "file {} is {} bytes; limit is {MAX_FILE_BYTES}",
                path.display(),
                metadata.len()
            ),
        });
    }
    Ok(())
}
