//! `start_recording` / `stop_recording` Tauri commands.

use std::path::PathBuf;

use serde::Serialize;
use tauri::{AppHandle, Manager, State};

use crate::audio::{start_recording, MAX_DURATION_SECONDS};
use crate::error::AppError;
use crate::state::{CapturedAudio, RecordingHandle, SharedState};

#[derive(Debug, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct RecordingStarted {
    pub out_path: String,
    pub sample_rate_hz: u32,
    pub channels: u16,
    pub max_duration_seconds: u32,
}

#[derive(Debug, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct RecordingFinished {
    pub path: String,
    pub duration_ms: u32,
    pub sample_rate_hz: u32,
    pub channels: u16,
}

#[tauri::command]
#[specta::specta]
pub async fn start_recording_cmd(
    app: AppHandle,
    state: State<'_, SharedState>,
) -> Result<RecordingStarted, AppError> {
    let data_dir = app
        .path()
        .app_local_data_dir()
        .map_err(|err| AppError::Io {
            path: "(app_local_data_dir)".to_string(),
            detail: err.to_string(),
        })?;
    let recordings_dir = data_dir.join("recordings");
    std::fs::create_dir_all(&recordings_dir).map_err(|err| AppError::Io {
        path: recordings_dir.display().to_string(),
        detail: err.to_string(),
    })?;

    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let out_path: PathBuf = recordings_dir.join(format!("recording-{stamp}.wav"));

    let mut guard = state.lock().await;
    if guard.recording.is_some() {
        return Err(AppError::RecordingAlreadyActive);
    }

    let (stopper, config) = start_recording(&out_path)?;
    guard.recording = Some(RecordingHandle {
        out_path: out_path.clone(),
        stopper,
    });
    guard.data_dir = Some(data_dir);

    Ok(RecordingStarted {
        out_path: out_path.display().to_string(),
        sample_rate_hz: config.sample_rate_hz,
        channels: config.channels,
        max_duration_seconds: MAX_DURATION_SECONDS as u32,
    })
}

#[tauri::command]
#[specta::specta]
pub async fn stop_recording_cmd(
    state: State<'_, SharedState>,
) -> Result<RecordingFinished, AppError> {
    let mut guard = state.lock().await;
    let handle = guard.recording.take().ok_or(AppError::NoActiveRecording)?;
    let out_path = handle.out_path.clone();
    let summary = handle.stopper.finish()?;
    guard.captured_audio = Some(CapturedAudio {
        path: out_path.clone(),
        duration_ms: summary.duration_ms,
        sample_rate_hz: summary.sample_rate_hz,
        channels: summary.channels,
    });
    Ok(RecordingFinished {
        path: out_path.display().to_string(),
        duration_ms: u32::try_from(summary.duration_ms).unwrap_or(u32::MAX),
        sample_rate_hz: summary.sample_rate_hz,
        channels: summary.channels,
    })
}
