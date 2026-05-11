//! Pass 2: per-image description.
//!
//! Reads the image bytes from disk, computes a SHA-256 over the raw bytes
//! (never over decoded pixel data), base64-encodes for transport, and sends
//! the image as the first content part with a short description prompt as
//! the second part. The Gemma 4 docs require image content before text.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::error::InferenceError;
use crate::http::{build_http_client, extract_text_content, post_chat, DEFAULT_MODEL};

/// Visual token budget. 280 is the Gemma 4 default per the model card and
/// the build guide; lower to 140 trades detail for latency.
pub const DEFAULT_VISUAL_TOKEN_BUDGET: u32 = 280;
const DEFAULT_MAX_TOKENS: u32 = 220;
const DEFAULT_TEMPERATURE: f32 = 0.2;
const DEFAULT_PROMPT: &str = "Describe the contents of this image in two or three sentences. \
Be concrete: name the setting, the visible objects, and any people or activity. \
Do not speculate about audio, intent, or anything not visible.";

/// Result of analysing a single image.
#[derive(Debug, Clone, Serialize)]
pub struct ImageAnalysis {
    /// Absolute path the analysis was run against.
    pub image_path: PathBuf,
    /// SHA-256 of the raw image bytes as read from disk. Hex-encoded.
    pub image_sha256_hex: String,
    /// Byte length of the image file on disk.
    pub image_bytes: u64,
    /// Visible-content description returned by the model.
    pub description: String,
    /// Visual token budget the pass used. Persisted on the result so the
    /// manifest can record the parameters that produced the description.
    pub visual_token_budget: u32,
    /// Wall-clock latency in milliseconds.
    pub latency_ms: u128,
}

/// Run pass 2 against a single image.
///
/// `endpoint` is the sidecar base URL, typically [`crate::DEFAULT_ENDPOINT`].
///
/// # Errors
///
/// Returns [`InferenceError::Io`] if the image cannot be read off disk, or
/// any of the transport/shape variants if the sidecar misbehaves.
pub async fn analyze_image(
    image_path: &Path,
    endpoint: &str,
) -> Result<ImageAnalysis, InferenceError> {
    analyze_image_with_budget(image_path, endpoint, DEFAULT_VISUAL_TOKEN_BUDGET).await
}

/// Variant of [`analyze_image`] with an explicit visual token budget.
pub async fn analyze_image_with_budget(
    image_path: &Path,
    endpoint: &str,
    visual_token_budget: u32,
) -> Result<ImageAnalysis, InferenceError> {
    let canonical = image_path
        .canonicalize()
        .map_err(|source| InferenceError::Io {
            path: image_path.display().to_string(),
            detail: "could not canonicalize image path. confirm the file exists and is readable."
                .to_string(),
            source,
        })?;
    let bytes = std::fs::read(&canonical).map_err(|source| InferenceError::Io {
        path: canonical.display().to_string(),
        detail: "could not read image bytes. confirm read permissions.".to_string(),
        source,
    })?;
    let image_sha256_hex = hex::encode(Sha256::digest(&bytes));
    let image_bytes = bytes.len() as u64;
    let mime = detect_mime(&canonical, &bytes);
    let data_url = format!("data:{};base64,{}", mime, BASE64.encode(&bytes));

    let body = json!({
        "model": DEFAULT_MODEL,
        "max_tokens": DEFAULT_MAX_TOKENS,
        "temperature": DEFAULT_TEMPERATURE,
        "visual_token_budget": visual_token_budget,
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "image_url", "image_url": {"url": data_url}},
                    {"type": "text", "text": DEFAULT_PROMPT}
                ]
            }
        ]
    });

    let http = build_http_client(endpoint)?;
    let started = std::time::Instant::now();
    let payload = post_chat(&http, endpoint, &body).await?;
    let description = extract_text_content(&payload)?;

    Ok(ImageAnalysis {
        image_path: canonical,
        image_sha256_hex,
        image_bytes,
        description,
        visual_token_budget,
        latency_ms: started.elapsed().as_millis(),
    })
}

/// Sniff the MIME type from the leading bytes, falling back to the file
/// extension. Only the formats Gemma 4 supports for vision input are
/// recognised; other formats default to `image/jpeg` to surface a clear
/// model-side error rather than silently encoding the wrong header.
fn detect_mime(path: &Path, bytes: &[u8]) -> &'static str {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        return "image/png";
    }
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return "image/jpeg";
    }
    if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return "image/webp";
    }
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("png") => "image/png",
        Some("webp") => "image/webp",
        _ => "image/jpeg",
    }
}
