//! HTTP client that asks the local sidecar to fill an [`IncidentReport`].
//!
//! The client uses the OpenAI `tools` parameter for function calling. The
//! mlx-vlm 0.5.x server (the dev/demo path documented in CLAUDE.md) supports
//! tool calls for Gemma 4 via `mlx_lm.tool_parsers.gemma4`; verified manually
//! against the running sidecar on 2026-05-10. See `docs/decisions/day2.md`.

use std::time::Duration;

use jsonschema::JSONSchema;
use serde_json::{json, Value};
use witness_core::IncidentReport;

use crate::error::InferenceError;
use crate::http::{
    assert_endpoint_is_loopback, DEFAULT_ENDPOINT, DEFAULT_MODEL, MAX_RESPONSE_BYTES,
    SIDECAR_TOKEN_ENV, SIDECAR_TOKEN_HEADER,
};
use crate::response::{extract_tool_arguments, TOOL_NAME};

/// Sampling temperature.
///
/// 0.2 keeps the model close to greedy while leaving headroom for the
/// schema-repair retries to pick a different completion when the first one
/// fails validation. Higher temperatures degraded structured output in the
/// Day 2 evaluation; lower temperatures made retries deterministic copies of
/// the failing first attempt.
pub const DEFAULT_TEMPERATURE: f32 = 0.2;
/// Top-p nucleus sampling threshold.
///
/// 0.9 is the value recommended in the Gemma 4 model card for instruction
/// following with structured output.
pub const DEFAULT_TOP_P: f32 = 0.9;
/// How many times to re-ask the model when its output fails schema validation.
///
/// 3 retries is the smallest number that empirically clears occasional
/// off-by-one severity errors without inflating per-transcript latency.
pub const DEFAULT_MAX_RETRIES: u32 = 3;
/// Token cap on the structure-incident pass. Public for manifest recording.
pub const DEFAULT_MAX_TOKENS: u32 = 800;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Fixed instruction prompt for the structure-incident pass. Public so the
/// manifest can record SHA-256(`SYSTEM_PROMPT`) without coupling to the
/// client internals.
pub const SYSTEM_PROMPT: &str = "You are an evidence-extraction assistant. Given a witness transcript, \
call the `record_incident` tool exactly once with the structured fields filled in from the transcript. \
Do not invent facts. \
\n\nStrict output rules:\
\n1. `timestamp` MUST be a full RFC 3339 datetime ending in `Z` if no timezone is given, e.g. `2024-11-08T23:00:00Z`. Never emit a timestamp without a timezone suffix.\
\n2. `location` is REQUIRED. Always include it with at least a `description` string. If the transcript names a place or address, use it; otherwise write `unknown`.\
\n3. `evidence_references` is REQUIRED and MUST always be present. If the transcript does not list specific files with hashes (it almost never does), emit an empty array `[]`. Do NOT fabricate sha256 values; the field requires a real 64-character hex hash.\
\n4. `narrative_summary` MUST be at least 20 characters and must paraphrase the transcript without adding facts.\
\n5. `severity` is an integer 1 (minor) to 5 (catastrophic). Choose conservatively.\
\n6. Omit optional fields entirely when the transcript does not state them. Do not emit empty strings or placeholder values.\
\n7. `incident_type` MUST be one of: safety_hazard, environmental, labor, harassment, property_damage, other.";

/// Outcome of a single `structure_incident` call.
#[derive(Debug, Clone)]
pub struct StructureOutcome {
    /// The validated incident report.
    pub report: IncidentReport,
    /// How many retries were used (0 means the first attempt was valid).
    pub retries_used: u32,
    /// Wall-clock latency across all attempts, in milliseconds.
    pub latency_ms: u128,
}

/// Reusable client around a single sidecar endpoint.
///
/// Holds an `reqwest::Client` so connections are pooled across calls.
#[derive(Debug, Clone)]
pub struct InferenceClient {
    endpoint: String,
    model: String,
    http: reqwest::Client,
    temperature: f32,
    top_p: f32,
    max_retries: u32,
}

impl InferenceClient {
    /// Build a client with default settings pointing at the local sidecar.
    pub fn new() -> Result<Self, InferenceError> {
        Self::with_endpoint(DEFAULT_ENDPOINT)
    }

    /// Build a client targeting a specific endpoint.
    pub fn with_endpoint(endpoint: &str) -> Result<Self, InferenceError> {
        assert_endpoint_is_loopback(endpoint)?;
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|source| InferenceError::Transport {
                endpoint: endpoint.to_string(),
                source,
            })?;
        Ok(Self {
            endpoint: endpoint.to_string(),
            model: DEFAULT_MODEL.to_string(),
            http,
            temperature: DEFAULT_TEMPERATURE,
            top_p: DEFAULT_TOP_P,
            max_retries: DEFAULT_MAX_RETRIES,
        })
    }

    /// Override the model id.
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// Override the retry budget.
    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Run the structuring pass against `transcript`, validating against `schema`.
    pub async fn structure_incident(
        &self,
        transcript: &str,
        schema: &Value,
    ) -> Result<StructureOutcome, InferenceError> {
        let validator = JSONSchema::compile(schema).map_err(|e| InferenceError::BadSchema {
            detail: e.to_string(),
        })?;

        let started = std::time::Instant::now();
        let mut last_error = String::new();
        let mut last_raw: Option<String> = None;

        for attempt in 0..=self.max_retries {
            let body = self.build_request(transcript, schema, last_raw.as_deref(), &last_error);
            let response = self.post(&body).await?;
            let arguments = match extract_tool_arguments(&response) {
                Ok(value) => value,
                Err(err) => {
                    last_error = err.to_string();
                    tracing::warn!(attempt, error = %last_error, "non-tool-call response");
                    continue;
                }
            };

            last_raw = Some(arguments.clone());
            let parsed: Value = match serde_json::from_str(&arguments) {
                Ok(v) => v,
                Err(source) => {
                    last_error = format!("tool arguments did not parse as JSON: {source}");
                    continue;
                }
            };

            if let Err(errors) = validator.validate(&parsed) {
                last_error = errors
                    .map(|e| format!("at {}: {}", e.instance_path, e))
                    .collect::<Vec<_>>()
                    .join("; ");
                tracing::warn!(attempt, error = %last_error, "schema validation failed");
                continue;
            }

            let report: IncidentReport = match serde_json::from_value(parsed) {
                Ok(r) => r,
                Err(source) => {
                    last_error = format!("matched schema but not Rust type: {source}");
                    continue;
                }
            };

            return Ok(StructureOutcome {
                report,
                retries_used: attempt,
                latency_ms: started.elapsed().as_millis(),
            });
        }

        Err(InferenceError::SchemaInvalid {
            attempts: self.max_retries + 1,
            last_error,
        })
    }

    fn build_request(
        &self,
        transcript: &str,
        schema: &Value,
        last_raw: Option<&str>,
        last_error: &str,
    ) -> Value {
        let mut user_text = format!(
            "Transcript follows between <transcript> tags.\n<transcript>\n{transcript}\n</transcript>\n\nCall `record_incident` exactly once with fields populated from the transcript."
        );
        if let Some(raw) = last_raw {
            user_text.push_str(&format!(
                "\n\nYour previous attempt failed schema validation.\nPrevious arguments:\n{raw}\nValidator error:\n{last_error}\n\nFix the errors and call the tool again."
            ));
        }

        json!({
            "model": self.model,
            "max_tokens": DEFAULT_MAX_TOKENS,
            "temperature": self.temperature,
            "top_p": self.top_p,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_text},
            ],
            "tools": [{
                "type": "function",
                "function": {
                    "name": TOOL_NAME,
                    "description": "Record a structured incident report extracted from the transcript.",
                    "parameters": schema,
                }
            }],
            "tool_choice": {"type": "function", "function": {"name": TOOL_NAME}},
        })
    }

    async fn post(&self, body: &Value) -> Result<Value, InferenceError> {
        let url = format!(
            "{}/v1/chat/completions",
            self.endpoint.trim_end_matches('/')
        );
        let mut request = self.http.post(&url).json(body);
        if let Ok(token) = std::env::var(SIDECAR_TOKEN_ENV) {
            if !token.is_empty() {
                request = request.header(SIDECAR_TOKEN_HEADER, token);
            }
        }
        let mut response = request
            .send()
            .await
            .map_err(|source| InferenceError::Transport {
                endpoint: self.endpoint.clone(),
                source,
            })?;
        let status = response.status();
        if let Some(content_length) = response.content_length() {
            if content_length as usize > MAX_RESPONSE_BYTES {
                return Err(InferenceError::ResponseTooLarge {
                    endpoint: self.endpoint.clone(),
                    cap_bytes: MAX_RESPONSE_BYTES,
                    seen_bytes: content_length as usize,
                });
            }
        }
        let mut bytes: Vec<u8> = Vec::new();
        loop {
            let chunk = response
                .chunk()
                .await
                .map_err(|source| InferenceError::Transport {
                    endpoint: self.endpoint.clone(),
                    source,
                })?;
            match chunk {
                Some(buf) => {
                    if bytes.len() + buf.len() > MAX_RESPONSE_BYTES {
                        return Err(InferenceError::ResponseTooLarge {
                            endpoint: self.endpoint.clone(),
                            cap_bytes: MAX_RESPONSE_BYTES,
                            seen_bytes: bytes.len() + buf.len(),
                        });
                    }
                    bytes.extend_from_slice(&buf);
                }
                None => break,
            }
        }
        if !status.is_success() {
            return Err(InferenceError::BadStatus {
                endpoint: self.endpoint.clone(),
                status: status.as_u16(),
                body: String::from_utf8_lossy(&bytes).chars().take(500).collect(),
            });
        }
        serde_json::from_slice(&bytes).map_err(|source| InferenceError::BadJson {
            body_snippet: String::from_utf8_lossy(&bytes).chars().take(500).collect(),
            source,
        })
    }
}

/// Convenience wrapper that builds a default client and calls
/// [`InferenceClient::structure_incident`].
pub async fn structure_incident(
    transcript: &str,
    schema: &Value,
) -> Result<StructureOutcome, InferenceError> {
    InferenceClient::new()?
        .structure_incident(transcript, schema)
        .await
}

/// Variant of [`structure_incident`] that lets callers pass a pre-built client.
pub async fn structure_incident_with(
    client: &InferenceClient,
    transcript: &str,
    schema: &Value,
) -> Result<StructureOutcome, InferenceError> {
    client.structure_incident(transcript, schema).await
}
