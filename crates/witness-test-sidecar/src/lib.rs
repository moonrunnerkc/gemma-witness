//! Hermetic OpenAI-compatible fake sidecar.
//!
//! Exists so the full capture-to-seal-to-verify pipeline can run in CI on
//! Linux and Windows, where the real mlx-vlm or mistralrs model can't boot.
//!
//! What it does NOT do:
//!   - Run a model. There is no inference here. Responses are precomputed
//!     fixture bytes chosen by classifying the incoming request.
//!   - Mock witness-core or witness-inference. Those crates make real HTTP
//!     calls against this server's address; everything inside witness-* runs
//!     unmodified.
//!
//! This is a mock at the network boundary, which CLAUDE.md explicitly allows.
//!
//! ## Release tripwire
//!
//! This crate is `publish = false` and gates its public surface behind the
//! `test-fixtures` feature (default-on so workspace tests work without
//! ceremony). Linking it from production code with `--features release`
//! triggers a compile-time error; the capture binary never sets that
//! feature, so reaching the error means a wiring mistake.

#[cfg(feature = "release")]
compile_error!(
    "witness-test-sidecar is a development-only fake. \
     it must never be linked from a production build. \
     remove the `release` feature flag, or, if it appeared via a transitive dependency, \
     replace the dependency with one that does not pull witness-test-sidecar in."
);

#[cfg(not(any(test, feature = "test-fixtures")))]
compile_error!(
    "witness-test-sidecar is gated behind the `test-fixtures` feature (default-on inside this workspace) \
     or a `#[cfg(test)]` context. enabling `default-features = false` without re-enabling `test-fixtures` \
     would let production code link the fake server; refusing to compile."
);

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// Handle returned by [`start`]. Drop it (or call [`Self::shutdown`]) to stop
/// the server.
pub struct FakeSidecar {
    pub endpoint: String,
    shutdown: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

impl FakeSidecar {
    /// Gracefully stop the server. Idempotent.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for FakeSidecar {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

/// Behavior overrides for the fake sidecar. Defaults match Gemma 4 E4B mlx
/// expectations as documented in `crates/witness-inference`.
#[derive(Clone, Debug)]
pub struct FakeConfig {
    /// The id returned by `GET /v1/models`. The seal command's fingerprint
    /// lookup is keyed off this. Default: the seeded mlx-community entry.
    pub model_id: String,
    /// Optional complete model list returned by `GET /v1/models`. When unset,
    /// the fake returns `model_id` as the only entry.
    pub listed_model_ids: Option<Vec<String>>,
    /// Pass-0 transcript text returned in `choices[0].message.content`.
    pub transcript: String,
    /// Pass-2 image-description text. Used for every image request.
    pub image_description: String,
    /// Pass-3 verdict ("consistent", "partially-consistent", "inconsistent").
    pub verdict: String,
    /// Pass-3 short reason string.
    pub consistency_reason: String,
    /// Pass-3 thinking-channel content. Stored verbatim in the bundle.
    pub reasoning_trace: String,
    /// Tool-call arguments JSON returned by pass 1. If `None`, the server
    /// fabricates a minimal incident_report that conforms to the schema.
    pub incident_arguments_json: Option<String>,
    /// When `Some`, every request must echo this value in the
    /// `X-Witness-Token` header or the server responds 401. Mirrors the
    /// production sidecar behaviour wired up under audit finding T-7/I-2.
    pub required_token: Option<String>,
    /// When `Some(n)`, the next `n` `/v1/chat/completions` responses are
    /// padded with junk JSON to exceed the response cap. Lets tests assert
    /// the streaming reader aborts rather than allocating to the cap.
    pub oversized_response_bytes: Option<usize>,
}

impl Default for FakeConfig {
    fn default() -> Self {
        Self {
            model_id: "mlx-community/gemma-4-e4b-it-4bit".to_string(),
            listed_model_ids: None,
            transcript: "I am standing at the corner of Front and Bay Street. A truck just rolled over and there is fuel leaking onto the road.".to_string(),
            image_description: "A delivery truck on its side at a four-way intersection, with fluid pooling on the asphalt and two pedestrians watching from across the crosswalk.".to_string(),
            verdict: "consistent".to_string(),
            consistency_reason: "image shows the overturned truck and roadway fuel that the transcript describes".to_string(),
            reasoning_trace: "Thinking: the transcript names an overturned truck with leaking fuel. The image shows a truck on its side with fluid on the asphalt. The locations and key facts agree.\n\n{\"verdict\":\"consistent\",\"reason\":\"image shows the overturned truck and roadway fuel that the transcript describes\"}".to_string(),
            incident_arguments_json: None,
            required_token: None,
            oversized_response_bytes: None,
        }
    }
}

/// Spin up a server bound to `127.0.0.1:0` and return its handle.
///
/// `endpoint` on the returned handle is the full base URL the client should
/// hit (`http://127.0.0.1:<port>`).
pub async fn start(config: FakeConfig) -> std::io::Result<FakeSidecar> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let endpoint = format!("http://{}", addr);
    let (tx, mut rx) = oneshot::channel::<()>();
    let state = Arc::new(config);

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut rx => break,
                accept = listener.accept() => {
                    let (stream, _) = match accept {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    let state = state.clone();
                    tokio::spawn(async move {
                        if let Err(err) = serve_connection(stream, state).await {
                            eprintln!("fake-sidecar connection error: {err}");
                        }
                    });
                }
            }
        }
    });

    Ok(FakeSidecar {
        endpoint,
        shutdown: Some(tx),
        handle: Some(handle),
    })
}

/// Convenience: start with default config and return the endpoint plus handle.
pub async fn start_default() -> std::io::Result<FakeSidecar> {
    start(FakeConfig::default()).await
}

async fn serve_connection(mut stream: TcpStream, state: Arc<FakeConfig>) -> Result<(), Infallible> {
    let request = match read_http_request(&mut stream).await {
        Ok(r) => r,
        Err(err) => {
            let _ = write_response(&mut stream, 400, "application/json", err.as_bytes()).await;
            return Ok(());
        }
    };
    let response = route(&request, &state);
    let body = response.body.to_string();
    let _ = write_response(
        &mut stream,
        response.status,
        "application/json",
        body.as_bytes(),
    )
    .await;
    Ok(())
}

struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
    headers: HashMap<String, String>,
}

struct HttpResponse {
    status: u16,
    body: Value,
}

async fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    let mut buf = Vec::with_capacity(8 * 1024);
    let mut tmp = [0u8; 8 * 1024];
    let header_end;
    loop {
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|err| format!("read: {err}"))?;
        if n == 0 {
            return Err("client closed before request was complete".to_string());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_double_crlf(&buf) {
            header_end = pos;
            break;
        }
        if buf.len() > 8 * 1024 * 1024 {
            return Err("request header too large".to_string());
        }
    }

    let header_text = std::str::from_utf8(&buf[..header_end])
        .map_err(|err| format!("non-utf8 in headers: {err}"))?
        .to_string();
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().ok_or("missing request line")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("missing method")?.to_string();
    let path = parts.next().ok_or("missing path")?.to_string();

    let mut content_length: usize = 0;
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if key == "content-length" {
                content_length = val.parse().unwrap_or(0);
            }
            headers.insert(key, val);
        }
    }

    let body_start = header_end + 4;
    let mut body = if buf.len() >= body_start {
        buf[body_start..].to_vec()
    } else {
        Vec::new()
    };

    while body.len() < content_length {
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|err| format!("read body: {err}"))?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);

    Ok(HttpRequest {
        method,
        path,
        body,
        headers,
    })
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "OK",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

fn route(req: &HttpRequest, config: &FakeConfig) -> HttpResponse {
    if let Some(required) = config.required_token.as_ref() {
        let provided = req
            .headers
            .get("x-witness-token")
            .map(|s| s.as_str())
            .unwrap_or("");
        if provided != required.as_str() {
            return HttpResponse {
                status: 401,
                body: json!({
                    "error": "X-Witness-Token header missing or does not match the per-launch shared secret"
                }),
            };
        }
    }
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/v1/models") => HttpResponse {
            status: 200,
            body: models_response(config),
        },
        ("POST", "/v1/handshake") => handle_handshake(&req.body),
        ("POST", "/v1/chat/completions") => handle_chat_completions(&req.body, config),
        _ => HttpResponse {
            status: 404,
            body: json!({ "error": format!("no route for {} {}", req.method, req.path) }),
        },
    }
}

fn models_response(config: &FakeConfig) -> Value {
    let ids = config
        .listed_model_ids
        .clone()
        .unwrap_or_else(|| vec![config.model_id.clone()]);
    let data: Vec<Value> = ids
        .into_iter()
        .map(|id| {
            json!({
                "id": id,
                "object": "model",
                "owned_by": "fake-sidecar"
            })
        })
        .collect();
    json!({
        "object": "list",
        "data": data
    })
}

fn handle_handshake(body: &[u8]) -> HttpResponse {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(err) => {
            return HttpResponse {
                status: 400,
                body: json!({ "error": format!("invalid JSON: {err}") }),
            };
        }
    };
    let nonce = parsed.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
    if nonce.is_empty() {
        return HttpResponse {
            status: 400,
            body: json!({ "error": "handshake body must carry a non-empty `nonce`" }),
        };
    }
    HttpResponse {
        status: 200,
        body: json!({ "nonce": nonce }),
    }
}

fn handle_chat_completions(body: &[u8], config: &FakeConfig) -> HttpResponse {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(err) => {
            return HttpResponse {
                status: 400,
                body: json!({ "error": format!("invalid JSON: {err}") }),
            };
        }
    };
    let kind = classify(&parsed);
    let mut response_body = build_response(kind, config);
    if let Some(size) = config.oversized_response_bytes {
        let mut padding = String::with_capacity(size);
        for _ in 0..size {
            padding.push('A');
        }
        if let Some(map) = response_body.as_object_mut() {
            map.insert("oversize_padding".to_string(), Value::String(padding));
        }
    }
    HttpResponse {
        status: 200,
        body: response_body,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PassKind {
    Transcribe,
    Structure,
    Image,
    Consistency,
}

fn classify(req: &Value) -> PassKind {
    if req.get("tools").is_some() {
        return PassKind::Structure;
    }
    let messages = req
        .get("messages")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let system = messages
        .iter()
        .find(|m| m.get("role").and_then(|v| v.as_str()) == Some("system"))
        .and_then(|m| m.get("content"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if system.starts_with("<|think|>") {
        return PassKind::Consistency;
    }
    let user_content = messages
        .iter()
        .find(|m| m.get("role").and_then(|v| v.as_str()) == Some("user"))
        .and_then(|m| m.get("content"));
    if let Some(Value::Array(parts)) = user_content {
        for part in parts {
            let ptype = part.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if ptype == "input_audio" {
                return PassKind::Transcribe;
            }
            if ptype == "image_url" {
                return PassKind::Image;
            }
        }
    }
    PassKind::Transcribe
}

fn build_response(kind: PassKind, config: &FakeConfig) -> Value {
    let id = "chatcmpl-fake-0000000000";
    let model = config.model_id.clone();
    match kind {
        PassKind::Transcribe => json!({
            "id": id,
            "object": "chat.completion",
            "model": model,
            "choices": [{
                "index": 0,
                "message": { "role": "assistant", "content": config.transcript },
                "finish_reason": "stop"
            }],
            "usage": { "prompt_tokens": 16, "completion_tokens": 16, "total_tokens": 32 }
        }),
        PassKind::Image => json!({
            "id": id,
            "object": "chat.completion",
            "model": model,
            "choices": [{
                "index": 0,
                "message": { "role": "assistant", "content": config.image_description },
                "finish_reason": "stop"
            }],
            "usage": { "prompt_tokens": 32, "completion_tokens": 32, "total_tokens": 64 }
        }),
        PassKind::Structure => {
            let arguments = match &config.incident_arguments_json {
                Some(custom) => custom.clone(),
                None => default_incident_arguments(&config.transcript),
            };
            json!({
                "id": id,
                "object": "chat.completion",
                "model": model,
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "tool_calls": [{
                            "id": "call_fake_0001",
                            "type": "function",
                            "function": {
                                "name": "record_incident",
                                "arguments": arguments
                            }
                        }]
                    },
                    "finish_reason": "tool_calls"
                }],
                "usage": { "prompt_tokens": 128, "completion_tokens": 64, "total_tokens": 192 }
            })
        }
        PassKind::Consistency => {
            let verdict_block = format!(
                "{{\"verdict\":\"{}\",\"reason\":\"{}\"}}",
                escape_json_string(&config.verdict),
                escape_json_string(&config.consistency_reason)
            );
            json!({
                "id": id,
                "object": "chat.completion",
                "model": model,
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": verdict_block,
                        "reasoning": config.reasoning_trace
                    },
                    "finish_reason": "stop"
                }],
                "usage": { "prompt_tokens": 256, "completion_tokens": 128, "total_tokens": 384 }
            })
        }
    }
}

fn escape_json_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn default_incident_arguments(transcript: &str) -> String {
    let safe = transcript
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .chars()
        .take(280)
        .collect::<String>();
    format!(
        "{{\"timestamp\":\"2026-05-14T12:00:00Z\",\"location\":{{\"description\":\"Corner of Front and Bay Street\"}},\"narrative_summary\":\"{}\",\"severity\":3,\"incident_type\":\"safety_hazard\",\"evidence_references\":[]}}",
        safe
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn models_endpoint_returns_configured_id() {
        let server = start_default().await.unwrap();
        let resp = reqwest::get(format!("{}/v1/models", server.endpoint))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: Value = resp.json().await.unwrap();
        assert_eq!(
            body["data"][0]["id"].as_str().unwrap(),
            "mlx-community/gemma-4-e4b-it-4bit"
        );
        server.shutdown().await;
    }

    #[tokio::test]
    async fn classify_routes_correctly() {
        let structure = json!({"tools": [{}], "messages": [{"role":"user","content":"x"}]});
        assert_eq!(classify(&structure), PassKind::Structure);

        let consistency = json!({"messages": [{"role":"system","content":"<|think|>x"}]});
        assert_eq!(classify(&consistency), PassKind::Consistency);

        let image = json!({"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:..."}},{"type":"text","text":"x"}]}]});
        assert_eq!(classify(&image), PassKind::Image);

        let transcribe = json!({"messages":[{"role":"user","content":[{"type":"input_text","text":"x"},{"type":"input_audio","input_audio":{"data":"/tmp/x.wav","format":"wav"}}]}]});
        assert_eq!(classify(&transcribe), PassKind::Transcribe);
    }
}
