//! `start_recording` / `stop_recording` Tauri commands.

use std::path::PathBuf;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::audio::{start_recording, MAX_DURATION_SECONDS, STREAM_ERROR_EVENT};
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

#[derive(Clone, serde::Serialize, specta::Type)]
struct StreamErrorPayload {
    detail: String,
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
    std::fs::create_dir_all(&recordings_dir)
        .map_err(|err| AppError::io_relative(&data_dir, &recordings_dir, err.to_string()))?;

    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let out_path: PathBuf = recordings_dir.join(format!("recording-{stamp}.wav"));

    let mut guard = state.lock().await;
    if guard.recording.is_some() {
        return Err(AppError::RecordingAlreadyActive);
    }

    let app_for_event = app.clone();
    let (stopper, config) = start_recording(&out_path, move |detail: &str| {
        let _ = app_for_event.emit(
            STREAM_ERROR_EVENT,
            StreamErrorPayload {
                detail: detail.to_string(),
            },
        );
    })?;
    guard.recording = Some(RecordingHandle {
        out_path: out_path.clone(),
        stopper,
    });

    Ok(RecordingStarted {
        out_path: crate::error::relativize_for_frontend(&data_dir, &out_path),
        sample_rate_hz: config.sample_rate_hz,
        channels: config.channels,
        max_duration_seconds: MAX_DURATION_SECONDS as u32,
    })
}

#[tauri::command]
#[specta::specta]
pub async fn stop_recording_cmd(
    app: AppHandle,
    state: State<'_, SharedState>,
) -> Result<RecordingFinished, AppError> {
    let data_dir = app
        .path()
        .app_local_data_dir()
        .map_err(|err| AppError::Io {
            path: "(app_local_data_dir)".to_string(),
            detail: err.to_string(),
        })?;
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
        path: crate::error::relativize_for_frontend(&data_dir, &out_path),
        duration_ms: u32::try_from(summary.duration_ms).unwrap_or(u32::MAX),
        sample_rate_hz: summary.sample_rate_hz,
        channels: summary.channels,
    })
}
