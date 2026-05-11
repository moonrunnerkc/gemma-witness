//! Typed errors surfaced from Tauri commands to the frontend.

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

    #[error("io error at {path:?}: {detail}.")]
    Io { path: String, detail: String },

    #[error("image picker rejected the selection: {detail}.")]
    ImageRejected { detail: String },

    #[error("inference pipeline failed: {detail}.")]
    Inference { detail: String },

    #[error("witness-core failure: {detail}.")]
    Core { detail: String },

    #[error("internal state error: {detail}. file a bug if this reproduces.")]
    State { detail: String },
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
