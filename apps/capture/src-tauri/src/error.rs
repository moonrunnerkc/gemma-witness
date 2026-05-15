//! Typed errors surfaced from Tauri commands to the frontend.

use std::path::Path;

use serde::{Serialize, Serializer};

/// Application-level error. `serde::Serialize` flattens the variant into a
/// stable string so the frontend can branch on it.
#[derive(Debug, thiserror::Error, specta::Type)]
pub enum AppError {
    #[error("no audio input device found: {detail}. confirm a microphone is connected and the OS has granted mic access to Gemma.Witness.")]
    NoAudioDevice { detail: String },

    #[error("audio device returned an unsupported configuration: {detail}. open Settings > Sound and pick a 16 kHz capable input.")]
    UnsupportedAudioConfig { detail: String },

    #[error("audio stream error: {detail}.")]
    AudioStream { detail: String },

    #[error("no recording is currently active. call start_recording first.")]
    NoActiveRecording,

    #[error("a recording is already in progress. stop it before starting another.")]
    RecordingAlreadyActive,

    #[error("no captured audio is staged. record audio before running inference or sealing.")]
    NoCapturedAudio,

    /// File-IO error. `Display` strips absolute paths down to a path relative
    /// to `app_local_data_dir` so the user-facing message cannot leak
    /// `/Users/<name>/Library/Application Support/...`. Absolute paths
    /// remain available to `tracing::error!` via [`Self::log_path`].
    #[error("io error at {path}: {detail}.")]
    Io { path: String, detail: String },

    #[error("image picker rejected the selection: {detail}.")]
    ImageRejected { detail: String },

    #[error("inference pipeline failed: {detail}.")]
    Inference { detail: String },

    #[error("witness-core failure: {detail}.")]
    Core { detail: String },

    #[error("internal state error: {detail}. file a bug if this reproduces.")]
    State { detail: String },

    #[error("another {operation} is already in progress; wait for it to finish before starting another. concurrent {operation} calls would race the captured state.")]
    AlreadyInProgress { operation: String },

    #[error(
        "sidecar token mismatch: the local sidecar did not echo the per-launch shared secret. \
         restart the app so a fresh token is issued, and confirm no rogue process is bound to port 8080."
    )]
    SidecarUnauthenticated,
}

impl AppError {
    /// Build an [`AppError::Io`] with a frontend-safe relative path. `data_dir`
    /// is the canonical `app_local_data_dir`. If `path` is inside it, the
    /// stored display string is the relative tail; otherwise the path is
    /// recorded as its file name only to avoid leaking the parent.
    pub fn io_relative(data_dir: &Path, path: &Path, detail: impl Into<String>) -> Self {
        let display = relativize_for_frontend(data_dir, path);
        Self::Io {
            path: display,
            detail: detail.into(),
        }
    }
}

/// Convert an absolute path to a frontend-safe display string. Strips the
/// `app_local_data_dir` prefix when present, otherwise returns the file
/// name with a `<external>` prefix so a path like
/// `/Users/jane/Pictures/incident.jpg` becomes `<external>/incident.jpg`.
pub fn relativize_for_frontend(data_dir: &Path, path: &Path) -> String {
    let canonical_data = data_dir.canonicalize().ok();
    let canonical_path = path.canonicalize().ok();
    if let (Some(root), Some(p)) = (canonical_data.as_ref(), canonical_path.as_ref()) {
        if let Ok(rel) = p.strip_prefix(root) {
            return rel.display().to_string();
        }
    }
    if let Ok(rel) = path.strip_prefix(data_dir) {
        return rel.display().to_string();
    }
    match path.file_name() {
        Some(name) => format!("<external>/{}", name.to_string_lossy()),
        None => "<unknown>".to_string(),
    }
}

impl Serialize for AppError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl From<witness_core::WitnessCoreError> for AppError {
    fn from(err: witness_core::WitnessCoreError) -> Self {
        AppError::Core {
            detail: err.to_string(),
        }
    }
}

impl From<witness_inference::InferenceError> for AppError {
    fn from(err: witness_inference::InferenceError) -> Self {
        AppError::Inference {
            detail: err.to_string(),
        }
    }
}
