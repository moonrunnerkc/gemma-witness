//! Process-wide state shared across Tauri commands.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::Mutex;
use witness_core::IncidentReport;
use witness_inference::passes::analyze_image::ImageAnalysis;

/// In-flight capture state. Held inside a `tokio::sync::Mutex` and exposed
/// via `tauri::State`.
#[derive(Default)]
pub struct CaptureState {
    pub recording: Option<RecordingHandle>,
    pub captured_audio: Option<CapturedAudio>,
    pub picked_images: Vec<PathBuf>,
    pub last_pipeline: Option<PipelineSnapshot>,
    pub reasoning_path: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,
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

/// Inference outputs the capture state needs to remember between
/// `run_inference` and `seal_bundle`.
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
}

/// Convenience alias for the shared state type used in command signatures.
pub type SharedState = Arc<Mutex<CaptureState>>;
