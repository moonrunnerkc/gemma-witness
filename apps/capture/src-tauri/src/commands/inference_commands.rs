//! `run_inference` Tauri command: drives the four-pass pipeline.

use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use witness_inference::run_full_pipeline_default;

use crate::error::AppError;
use crate::state::{PipelineSnapshot, SharedState};

#[derive(Debug, Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct InferenceSummary {
    pub transcript: String,
    pub narrative_summary: String,
    pub structured_report_json: String,
    pub consistency_verdict: String,
    pub consistency_reason: String,
    pub image_descriptions: Vec<String>,
    pub total_latency_ms: u32,
    pub reasoning_trace_path: String,
}

#[tauri::command]
#[specta::specta]
pub async fn run_inference_cmd(
    app: AppHandle,
    state: State<'_, SharedState>,
) -> Result<InferenceSummary, AppError> {
    let data_dir = derive_data_dir(&app)?;

    // Re-entrancy guard (audit T-9). Reject overlapping inference calls
    // before they can race the last_pipeline write.
    let (audio_path, image_paths) = {
        let mut guard = state.lock().await;
        if guard.running_inference {
            return Err(AppError::AlreadyInProgress {
                operation: "inference".to_string(),
            });
        }
        let audio = guard
            .captured_audio
            .as_ref()
            .ok_or(AppError::NoCapturedAudio)?
            .path
            .clone();
        let images: Vec<std::path::PathBuf> = guard
            .picked_images
            .iter()
            .map(|i| i.staged_path.clone())
            .collect();
        guard.running_inference = true;
        (audio, images)
    };

    let result = run_inference_inner(&app, &state, &data_dir, &audio_path, &image_paths).await;

    {
        let mut guard = state.lock().await;
        guard.running_inference = false;
    }
    result
}

async fn run_inference_inner(
    _app: &AppHandle,
    state: &State<'_, SharedState>,
    data_dir: &std::path::Path,
    audio_path: &std::path::Path,
    image_paths: &[std::path::PathBuf],
) -> Result<InferenceSummary, AppError> {
    let schema_path = workspace_schema_path();
    let schema_text = std::fs::read_to_string(&schema_path).map_err(|err| {
        tracing::error!(?schema_path, %err, "could not read incident schema");
        AppError::io_relative(
            data_dir,
            &schema_path,
            format!("read incident schema: {err}"),
        )
    })?;
    let schema: serde_json::Value =
        serde_json::from_str(&schema_text).map_err(|err| AppError::Inference {
            detail: format!("parse incident-schema.json: {err}"),
        })?;

    let pipeline = run_full_pipeline_default(audio_path, image_paths, &schema).await?;

    let trace_dir = data_dir.join("reasoning");
    std::fs::create_dir_all(&trace_dir).map_err(|err| {
        tracing::error!(path = ?trace_dir, %err, "create reasoning dir");
        AppError::io_relative(data_dir, &trace_dir, err.to_string())
    })?;
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let reasoning_path = trace_dir.join(format!("reasoning-{stamp}.txt"));
    std::fs::write(
        &reasoning_path,
        pipeline.consistency.reasoning_trace.as_bytes(),
    )
    .map_err(|err| {
        tracing::error!(path = ?reasoning_path, %err, "write reasoning trace");
        AppError::io_relative(
            data_dir,
            &reasoning_path,
            format!("write reasoning trace: {err}"),
        )
    })?;

    let image_descriptions: Vec<String> = pipeline
        .images
        .iter()
        .map(|i| i.description.clone())
        .collect();
    let narrative_summary = pipeline.structure.report.narrative_summary.clone();
    let structured_report_json = serde_json::to_string_pretty(&pipeline.structure.report)
        .unwrap_or_else(|_| "<unable to render report>".to_string());

    let summary = InferenceSummary {
        transcript: pipeline.transcribe.transcript.clone(),
        narrative_summary,
        structured_report_json,
        consistency_verdict: pipeline.consistency.verdict.clone(),
        consistency_reason: pipeline.consistency.reason.clone(),
        image_descriptions: image_descriptions.clone(),
        total_latency_ms: u32::try_from(pipeline.total_latency_ms).unwrap_or(u32::MAX),
        reasoning_trace_path: crate::error::relativize_for_frontend(data_dir, &reasoning_path),
    };

    let pinned_audio_sha256 = pipeline.transcribe.audio_sha256_hex.clone();
    let pinned_image_sha256s: Vec<String> = pipeline
        .images
        .iter()
        .map(|i| i.image_sha256_hex.clone())
        .collect();

    {
        let mut guard = state.lock().await;
        guard.last_pipeline = Some(PipelineSnapshot {
            transcript: pipeline.transcribe.transcript,
            report: pipeline.structure.report,
            images: pipeline.images,
            consistency_verdict: pipeline.consistency.verdict,
            consistency_reason: pipeline.consistency.reason,
            reasoning_trace: pipeline.consistency.reasoning_trace,
            total_latency_ms: pipeline.total_latency_ms,
            pinned_audio_sha256,
            pinned_image_sha256s,
        });
        guard.reasoning_path = Some(reasoning_path);
    }

    Ok(summary)
}

fn workspace_schema_path() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../../spec/incident-schema.json");
    p
}

fn derive_data_dir(app: &AppHandle) -> Result<std::path::PathBuf, AppError> {
    app.path().app_local_data_dir().map_err(|err| AppError::Io {
        path: "(app_local_data_dir)".to_string(),
        detail: err.to_string(),
    })
}
