//! Minimal shared transport helpers around the local sidecar.
//!
//! Each pass builds its own request body, but every pass posts to the same
//! `/v1/chat/completions` endpoint and unwraps the same error shapes. Sharing
//! the transport keeps the per-pass modules focused on prompt construction
//! and response parsing.

use std::time::Duration;

use serde_json::Value;

use crate::error::InferenceError;

/// Default sidecar base URL. Matches the mlx-vlm server bound in
/// `inference/mlx-sidecar/start.sh`.
pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:8080";
/// Gemma 4 E4B served by the sidecar.
pub const DEFAULT_MODEL: &str = "mlx-community/gemma-4-e4b-it-4bit";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

/// Build a `reqwest::Client` with the sidecar timeout pre-set.
pub(crate) fn build_http_client(endpoint: &str) -> Result<reqwest::Client, InferenceError> {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|source| InferenceError::Transport {
            endpoint: endpoint.to_string(),
            source,
        })
}

/// POST `body` to `{endpoint}/v1/chat/completions` and return the parsed JSON.
///
/// Wraps every transport/HTTP/JSON failure mode in a typed
/// [`InferenceError`] so callers don't propagate raw `reqwest::Error`.
pub(crate) async fn post_chat(
    http: &reqwest::Client,
    endpoint: &str,
    body: &Value,
) -> Result<Value, InferenceError> {
    let url = format!("{}/v1/chat/completions", endpoint.trim_end_matches('/'));
    let response =
        http.post(&url)
            .json(body)
            .send()
            .await
            .map_err(|source| InferenceError::Transport {
                endpoint: endpoint.to_string(),
                source,
            })?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|source| InferenceError::Transport {
            endpoint: endpoint.to_string(),
            source,
        })?;
    if !status.is_success() {
        return Err(InferenceError::BadStatus {
            endpoint: endpoint.to_string(),
            status: status.as_u16(),
            body: String::from_utf8_lossy(&bytes).chars().take(500).collect(),
        });
    }
    serde_json::from_slice(&bytes).map_err(|source| InferenceError::BadJson {
        body_snippet: String::from_utf8_lossy(&bytes).chars().take(500).collect(),
        source,
    })
}

/// Ask the sidecar which model it is serving by calling `GET /v1/models` and
/// returning the `id` of the first entry. Used by the seal path to pick the
/// correct fingerprint registry entry at runtime.
pub async fn fetch_active_model_id(
    http: &reqwest::Client,
    endpoint: &str,
) -> Result<String, InferenceError> {
    let url = format!("{}/v1/models", endpoint.trim_end_matches('/'));
    let response = http
        .get(&url)
        .send()
        .await
        .map_err(|source| InferenceError::Transport {
            endpoint: endpoint.to_string(),
            source,
        })?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|source| InferenceError::Transport {
            endpoint: endpoint.to_string(),
            source,
        })?;
    if !status.is_success() {
        return Err(InferenceError::BadStatus {
            endpoint: endpoint.to_string(),
            status: status.as_u16(),
            body: String::from_utf8_lossy(&bytes).chars().take(500).collect(),
        });
    }
    let parsed: Value =
        serde_json::from_slice(&bytes).map_err(|source| InferenceError::BadJson {
            body_snippet: String::from_utf8_lossy(&bytes).chars().take(500).collect(),
            source,
        })?;
    let id = parsed
        .pointer("/data/0/id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| InferenceError::BadShape {
            field: "data[0].id".to_string(),
            detail: "GET /v1/models returned no model entries. confirm the sidecar is fully loaded before sealing".to_string(),
        })?;
    Ok(id.to_string())
}

/// Convenience around [`fetch_active_model_id`] that builds a one-shot client.
pub async fn fetch_active_model_id_default(endpoint: &str) -> Result<String, InferenceError> {
    let http = build_http_client(endpoint)?;
    fetch_active_model_id(&http, endpoint).await
}

/// Extract `choices[0].message.content` as a UTF-8 string, or fail with a
/// precise [`InferenceError::BadShape`].
pub(crate) fn extract_text_content(payload: &Value) -> Result<String, InferenceError> {
    let content = payload
        .pointer("/choices/0/message/content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| InferenceError::BadShape {
            field: "choices[0].message.content".to_string(),
            detail: "missing, null, or not a string. raise max_tokens or check the prompt."
                .to_string(),
        })?;
    Ok(content.to_string())
}

/// Extract `choices[0].message.reasoning` (the verbatim thinking-channel
/// content emitted by mlx-vlm when the system prompt is prefixed with the
/// `<|think|>` token). Returns the string byte-for-byte as the sidecar
/// returned it. No trimming, no pretty-printing.
pub(crate) fn extract_reasoning(payload: &Value) -> Result<String, InferenceError> {
    let reasoning = payload
        .pointer("/choices/0/message/reasoning")
        .and_then(|v| v.as_str())
        .ok_or_else(|| InferenceError::BadShape {
            field: "choices[0].message.reasoning".to_string(),
            detail: "thinking-channel output missing. confirm `<|think|>` prefixes the system prompt and max_tokens is high enough for the model to finish thinking."
                .to_string(),
        })?;
    Ok(reasoning.to_string())
}
