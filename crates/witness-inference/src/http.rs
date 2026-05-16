//! Minimal shared transport helpers around the local sidecar.
//!
//! Each pass builds its own request body, but every pass posts to the same
//! `/v1/chat/completions` endpoint and unwraps the same error shapes. Sharing
//! the transport keeps the per-pass modules focused on prompt construction
//! and response parsing.

use std::time::Duration;

use rand::RngCore;
use serde_json::{json, Value};

use crate::error::InferenceError;

/// Default sidecar base URL. Matches the mlx-vlm server bound in
/// `inference/mlx-sidecar/start.sh`.
pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:8080";
/// Gemma 4 served by the sidecar.
pub const DEFAULT_MODEL: &str = "mlx-community/gemma-4-e4b-it-4bit";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum bytes accepted from a single sidecar response. Real Gemma 4
/// completions are well under 100 KB; this cap (10 MiB) is large enough to
/// never legitimately trip and small enough to stop a runaway sidecar from
/// OOM'ing the capture app.
pub const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
/// Environment variable name the per-launch shared secret is read from. The
/// capture app sets this when spawning child processes; manual launches
/// without it cannot exercise the authenticated path.
pub const SIDECAR_TOKEN_ENV: &str = "GW_SIDECAR_TOKEN";
/// HTTP header carrying the per-launch shared secret on every request.
pub const SIDECAR_TOKEN_HEADER: &str = "X-Witness-Token";

/// Assert that `endpoint` points at a loopback URL the capture app is
/// allowed to talk to. The capture app is offline-only by policy, so any
/// non-loopback endpoint is a footgun that would ship audio/image content
/// to whatever responded.
///
/// Accepted forms:
/// - `http://127.0.0.1[:port][/path]`
/// - `http://[::1][:port][/path]`
/// - `unix://<path>` (reserved for the future UDS transport)
pub fn assert_endpoint_is_loopback(endpoint: &str) -> Result<(), InferenceError> {
    if endpoint.starts_with("http://127.")
        || endpoint.starts_with("http://[::1]")
        || endpoint.starts_with("unix://")
    {
        return Ok(());
    }
    Err(InferenceError::EndpointNotLoopback {
        endpoint: endpoint.to_string(),
    })
}

/// Build a `reqwest::Client` with the sidecar timeouts pre-set.
///
/// The connect timeout (5 s) caps how long a TCP handshake can stall before
/// the call fails fast; the request timeout (300 s) is the outer ceiling on
/// total inference time. Add a per-chunk reader timeout once the streaming
/// reader lands; today the 5 s connect timeout already removes the worst of
/// the slowloris surface.
pub(crate) fn build_http_client(endpoint: &str) -> Result<reqwest::Client, InferenceError> {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .build()
        .map_err(|source| InferenceError::Transport {
            endpoint: endpoint.to_string(),
            source,
        })
}

/// Read a streaming response body, capped at [`MAX_RESPONSE_BYTES`]. Errors
/// past the cap rather than allocating to the full Content-Length.
async fn read_capped_body(
    mut response: reqwest::Response,
    endpoint: &str,
) -> Result<Vec<u8>, InferenceError> {
    if let Some(content_length) = response.content_length() {
        if content_length as usize > MAX_RESPONSE_BYTES {
            return Err(InferenceError::ResponseTooLarge {
                endpoint: endpoint.to_string(),
                cap_bytes: MAX_RESPONSE_BYTES,
                seen_bytes: content_length as usize,
            });
        }
    }
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let chunk = response
            .chunk()
            .await
            .map_err(|source| InferenceError::Transport {
                endpoint: endpoint.to_string(),
                source,
            })?;
        match chunk {
            Some(bytes) => {
                if buf.len() + bytes.len() > MAX_RESPONSE_BYTES {
                    return Err(InferenceError::ResponseTooLarge {
                        endpoint: endpoint.to_string(),
                        cap_bytes: MAX_RESPONSE_BYTES,
                        seen_bytes: buf.len() + bytes.len(),
                    });
                }
                buf.extend_from_slice(&bytes);
            }
            None => break,
        }
    }
    Ok(buf)
}

fn token_from_env() -> Option<String> {
    std::env::var(SIDECAR_TOKEN_ENV)
        .ok()
        .filter(|s| !s.is_empty())
}

/// POST `body` to `{endpoint}/v1/chat/completions` and return the parsed JSON.
///
/// Wraps every transport/HTTP/JSON failure mode in a typed
/// [`InferenceError`] so callers don't propagate raw `reqwest::Error`. When
/// the [`SIDECAR_TOKEN_ENV`] variable is set, the call includes the
/// [`SIDECAR_TOKEN_HEADER`] so the sidecar can reject any unauthenticated
/// caller racing for the same port.
pub(crate) async fn post_chat(
    http: &reqwest::Client,
    endpoint: &str,
    body: &Value,
) -> Result<Value, InferenceError> {
    assert_endpoint_is_loopback(endpoint)?;
    let url = format!("{}/v1/chat/completions", endpoint.trim_end_matches('/'));
    let mut request = http.post(&url).json(body);
    if let Some(token) = token_from_env() {
        request = request.header(SIDECAR_TOKEN_HEADER, token);
    }
    let response = request
        .send()
        .await
        .map_err(|source| InferenceError::Transport {
            endpoint: endpoint.to_string(),
            source,
        })?;
    let status = response.status();
    let bytes = read_capped_body(response, endpoint).await?;
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

/// Ask the sidecar which model it is serving by calling `GET /v1/models`.
///
/// Some sidecars list every locally cached model rather than the single model
/// passed at startup. In that case, prefer `GW_SIDECAR_MODEL` when set, then
/// the compiled default Gemma model. Only fall back to the first row when the
/// sidecar reports exactly one model.
pub async fn fetch_active_model_id(
    http: &reqwest::Client,
    endpoint: &str,
) -> Result<String, InferenceError> {
    assert_endpoint_is_loopback(endpoint)?;
    let url = format!("{}/v1/models", endpoint.trim_end_matches('/'));
    let mut request = http.get(&url);
    if let Some(token) = token_from_env() {
        request = request.header(SIDECAR_TOKEN_HEADER, token);
    }
    let response = request
        .send()
        .await
        .map_err(|source| InferenceError::Transport {
            endpoint: endpoint.to_string(),
            source,
        })?;
    let status = response.status();
    let bytes = read_capped_body(response, endpoint).await?;
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
    let ids = model_ids_from_response(&parsed)?;
    let configured = std::env::var("GW_SIDECAR_MODEL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_MODEL.to_string());
    if ids.iter().any(|id| id == &configured) {
        return Ok(configured);
    }
    if ids.len() == 1 {
        return Ok(ids[0].clone());
    }
    Err(InferenceError::BadShape {
        field: "data[].id".to_string(),
        detail: format!(
            "GET /v1/models returned multiple cached models but not the configured model {configured:?}: {}. set GW_SIDECAR_MODEL to the model launched by the sidecar, or start the default Gemma sidecar.",
            ids.join(", ")
        ),
    })
}

/// Convenience around [`fetch_active_model_id`] that builds a one-shot client.
pub async fn fetch_active_model_id_default(endpoint: &str) -> Result<String, InferenceError> {
    let http = build_http_client(endpoint)?;
    fetch_active_model_id(&http, endpoint).await
}

fn model_ids_from_response(parsed: &Value) -> Result<Vec<String>, InferenceError> {
    let entries = parsed
        .get("data")
        .and_then(|v| v.as_array())
        .ok_or_else(|| InferenceError::BadShape {
            field: "data".to_string(),
            detail: "GET /v1/models did not return a data array".to_string(),
        })?;
    let ids: Vec<String> = entries
        .iter()
        .filter_map(|entry| entry.get("id").and_then(|v| v.as_str()))
        .map(str::to_string)
        .collect();
    if ids.is_empty() {
        return Err(InferenceError::BadShape {
            field: "data[].id".to_string(),
            detail: "GET /v1/models returned no model ids. confirm the sidecar is fully loaded before sealing".to_string(),
        });
    }
    Ok(ids)
}

/// Verify the local sidecar shares the per-launch token by POSTing a random
/// nonce to `/v1/handshake` and confirming the response echoes the same
/// nonce back. The sidecar implementation MUST validate the
/// [`SIDECAR_TOKEN_HEADER`] before reading the body.
///
/// Returns Ok(()) on a clean round trip. Surfaces [`InferenceError::HandshakeFailed`]
/// when the sidecar's nonce does not match.
pub async fn handshake(http: &reqwest::Client, endpoint: &str) -> Result<(), InferenceError> {
    assert_endpoint_is_loopback(endpoint)?;
    let mut nonce_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce_hex = hex::encode(nonce_bytes);
    let url = format!("{}/v1/handshake", endpoint.trim_end_matches('/'));
    let mut request = http.post(&url).json(&json!({ "nonce": nonce_hex.clone() }));
    if let Some(token) = token_from_env() {
        request = request.header(SIDECAR_TOKEN_HEADER, token);
    }
    let response = request
        .send()
        .await
        .map_err(|source| InferenceError::Transport {
            endpoint: endpoint.to_string(),
            source,
        })?;
    let status = response.status();
    let bytes = read_capped_body(response, endpoint).await?;
    if status.as_u16() == 401 {
        return Err(InferenceError::HandshakeFailed {
            endpoint: endpoint.to_string(),
            detail: "sidecar returned 401: per-launch shared secret was not accepted".to_string(),
        });
    }
    if !status.is_success() {
        return Err(InferenceError::HandshakeFailed {
            endpoint: endpoint.to_string(),
            detail: format!(
                "sidecar returned http {}: {}",
                status.as_u16(),
                String::from_utf8_lossy(&bytes)
                    .chars()
                    .take(200)
                    .collect::<String>()
            ),
        });
    }
    let parsed: Value =
        serde_json::from_slice(&bytes).map_err(|source| InferenceError::BadJson {
            body_snippet: String::from_utf8_lossy(&bytes).chars().take(200).collect(),
            source,
        })?;
    let echoed = parsed
        .get("nonce")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if echoed != nonce_hex {
        return Err(InferenceError::HandshakeFailed {
            endpoint: endpoint.to_string(),
            detail: format!(
                "sidecar echoed nonce {echoed:?} but client sent {nonce_hex:?}; the responding process is not the sidecar this app launched"
            ),
        });
    }
    Ok(())
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
