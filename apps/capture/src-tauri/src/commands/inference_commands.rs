//! `run_inference` Tauri command: drives the four-pass pipeline.

use serde::Serialize;
use tauri::State;
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
    state: State<'_, SharedState>,
) -> Result<InferenceSummary, AppError> {
    let (audio_path, image_paths, data_dir) = {
        let guard = state.lock().await;
        let audio = guard
            .captured_audio
            .as_ref()
            .ok_or(AppError::NoCapturedAudio)?
            .path
            .clone();
        let images = guard.picked_images.clone();
        let data_dir = guard.data_dir.clone().ok_or_else(|| AppError::State {
            detail: "app_local_data_dir was not initialized; call initialize_device first"
                .to_string(),
        })?;
        (audio, images, data_dir)
    };

    let schema_path = workspace_schema_path();
    let schema_text = std::fs::read_to_string(&schema_path).map_err(|err| AppError::Io {
        path: schema_path.display().to_string(),
        detail: format!("read incident schema: {err}"),
    })?;
    let schema: serde_json::Value =
        serde_json::from_str(&schema_text).map_err(|err| AppError::Inference {
            detail: format!("parse incident-schema.json: {err}"),
        })?;

    let pipeline = run_full_pipeline_default(&audio_path, &image_paths, &schema).await?;

    let trace_dir = data_dir.join("reasoning");
    std::fs::create_dir_all(&trace_dir).map_err(|err| AppError::Io {
        path: trace_dir.display().to_string(),
        detail: err.to_string(),
    })?;
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let reasoning_path = trace_dir.join(format!("reasoning-{stamp}.txt"));
    std::fs::write(
        &reasoning_path,
        pipeline.consistency.reasoning_trace.as_bytes(),
    )
    .map_err(|err| AppError::Io {
        path: reasoning_path.display().to_string(),
        detail: format!("write reasoning trace: {err}"),
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
        reasoning_trace_path: reasoning_path.display().to_string(),
    };

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
