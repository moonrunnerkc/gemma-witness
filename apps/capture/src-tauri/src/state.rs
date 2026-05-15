//! Process-wide state shared across Tauri commands.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::Mutex;
use witness_core::IncidentReport;
use witness_inference::passes::analyze_image::ImageAnalysis;

/// In-flight capture state. Held inside a `tokio::sync::Mutex` and exposed
/// via `tauri::State`.
///
/// `data_dir` is deliberately not cached here. Each command derives it from
/// `AppHandle::path().app_local_data_dir()` per call so a future settings
/// command cannot redirect writes by mutating a shared field.
#[derive(Default)]
pub struct CaptureState {
    pub recording: Option<RecordingHandle>,
    pub captured_audio: Option<CapturedAudio>,
    pub picked_images: Vec<PickedImage>,
    pub last_pipeline: Option<PipelineSnapshot>,
    pub reasoning_path: Option<PathBuf>,
    /// Re-entrancy guard for `run_inference_cmd`. Two concurrent inference
    /// runs would race their `last_pipeline` writes and the seal step would
    /// pick whichever finished last.
    pub running_inference: bool,
    /// Re-entrancy guard for `seal_bundle_cmd`. Two concurrent seals would
    /// race their output paths.
    pub running_seal: bool,
    /// Per-launch shared secret the sidecar must echo on every request.
    /// Set once on `initialize_device` and cleared on app exit. None means
    /// authentication is not yet established and inference/seal must refuse.
    pub sidecar_token: Option<String>,
    /// True after a successful `/v1/handshake` round-trip with the sidecar
    /// during this app launch.
    pub sidecar_handshake_ok: bool,
}

/// Handle to a live cpal recording. Dropping the handle stops the stream and
/// flushes the WAV writer.
pub struct RecordingHandle {
    pub out_path: PathBuf,
    pub stopper: crate::audio::RecordingStopper,
}

/// Metadata for the most recently completed recording.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CapturedAudio {
    pub path: PathBuf,
    pub duration_ms: u64,
    pub sample_rate_hz: u32,
    pub channels: u16,
}

/// One image the user picked. The bytes are copied into a per-capture staging
/// directory on pick so the inference pipeline and the seal step read the
/// same bytes even if the source-of-truth file on the user's filesystem is
/// later swapped or sync'd over.
#[derive(Debug, Clone)]
pub struct PickedImage {
    /// In-app staging path under `app_local_data_dir`.
    pub staged_path: PathBuf,
}

/// Inference outputs the capture state needs to remember between
/// `run_inference` and `seal_bundle`. Pinned hashes are carried through so
/// the seal step can refuse to sign assets that changed under it between
/// inference and the user clicking Seal.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PipelineSnapshot {
    pub transcript: String,
    pub report: IncidentReport,
    pub images: Vec<ImageAnalysis>,
    pub consistency_verdict: String,
    pub consistency_reason: String,
    pub reasoning_trace: String,
    pub total_latency_ms: u128,
    /// SHA-256 (hex) of the audio bytes the inference pipeline read. The
    /// seal step recomputes the hash from on-disk bytes and aborts on
    /// mismatch (audit finding T-1/V-3).
    pub pinned_audio_sha256: String,
    /// SHA-256 (hex) of each image the inference pipeline read, in pick
    /// order. Matches `picked_images`.
    pub pinned_image_sha256s: Vec<String>,
}

/// Convenience alias for the shared state type used in command signatures.
pub type SharedState = Arc<Mutex<CaptureState>>;
