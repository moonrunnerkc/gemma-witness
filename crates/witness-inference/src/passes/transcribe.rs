//! Pass 0: transcribe a WAV file via the local sidecar.
//!
//! mlx-vlm's audio content part expects a filesystem path, not base64, so we
//! pass the canonicalized absolute path. The bytes hashed for the manifest
//! are the bytes read from disk, never re-encoded.

use std::path::{Path, PathBuf};

use serde_json::json;
use sha2::{Digest, Sha256};

use crate::error::InferenceError;
use crate::http::{build_http_client, extract_text_content, post_chat, DEFAULT_MODEL};

const DEFAULT_PROMPT: &str =
    "Transcribe this audio verbatim. Output only the transcript text, no labels or quotes.";
const DEFAULT_MAX_TOKENS: u32 = 500;
const DEFAULT_TEMPERATURE: f32 = 0.0;

/// Result of a single transcribe pass.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TranscribeOutcome {
    /// Verbatim transcript text returned by the model.
    pub transcript: String,
    /// SHA-256 of the raw WAV bytes as read from disk. Hex-encoded.
    pub audio_sha256_hex: String,
    /// Byte length of the WAV file on disk.
    pub audio_bytes: u64,
    /// Wall-clock latency in milliseconds.
    pub latency_ms: u128,
}

/// Transcribe the WAV at `audio_path` against the sidecar at `endpoint`.
///
/// # Errors
///
/// Returns [`InferenceError::Io`] if the WAV cannot be read off disk, or any
/// of the transport/shape variants if the sidecar misbehaves.
pub async fn transcribe(
    audio_path: &Path,
    endpoint: &str,
) -> Result<TranscribeOutcome, InferenceError> {
    let canonical: PathBuf = audio_path
        .canonicalize()
        .map_err(|source| InferenceError::Io {
            path: audio_path.display().to_string(),
            detail: "could not canonicalize audio path. confirm the file exists and is readable."
                .to_string(),
            source,
        })?;
    let bytes = std::fs::read(&canonical).map_err(|source| InferenceError::Io {
        path: canonical.display().to_string(),
        detail: "could not read audio bytes. confirm read permissions.".to_string(),
        source,
    })?;
    let audio_bytes = bytes.len() as u64;
    let audio_sha256_hex = hex::encode(Sha256::digest(&bytes));

    let body = json!({
        "model": DEFAULT_MODEL,
        "max_tokens": DEFAULT_MAX_TOKENS,
        "temperature": DEFAULT_TEMPERATURE,
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "input_text", "text": DEFAULT_PROMPT},
                    {
                        "type": "input_audio",
                        "input_audio": {
                            "data": canonical.to_string_lossy(),
                            "format": "wav"
                        }
                    }
                ]
            }
        ]
    });

    let http = build_http_client(endpoint)?;
    let started = std::time::Instant::now();
    let payload = post_chat(&http, endpoint, &body).await?;
    let transcript = extract_text_content(&payload)?;

    Ok(TranscribeOutcome {
        transcript,
        audio_sha256_hex,
        audio_bytes,
        latency_ms: started.elapsed().as_millis(),
    })
}
