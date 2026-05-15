//! Typed errors produced by the inference client.

/// Errors raised by `witness-inference`.
#[derive(Debug, thiserror::Error)]
pub enum InferenceError {
    /// The HTTP request to the sidecar failed at the transport layer.
    #[error("transport failure talking to sidecar at {endpoint}: {source}. confirm the sidecar is running (inference/mlx-sidecar/start.sh).")]
    Transport {
        endpoint: String,
        #[source]
        source: reqwest::Error,
    },

    /// The sidecar returned a non-2xx HTTP status.
    #[error(
        "sidecar at {endpoint} returned http {status}: {body}. inspect evidence/.../sidecar.log."
    )]
    BadStatus {
        endpoint: String,
        status: u16,
        body: String,
    },

    /// The sidecar response did not parse as JSON.
    #[error("sidecar response was not valid JSON: {source}. body snippet: {body_snippet:?}.")]
    BadJson {
        body_snippet: String,
        #[source]
        source: serde_json::Error,
    },

    /// The sidecar response was JSON but did not match the OpenAI shape we expect.
    #[error("sidecar response missing field {field}: {detail}. enable tracing=debug to inspect the raw payload.")]
    BadShape { field: String, detail: String },

    /// The sidecar produced a tool call whose `arguments` did not parse.
    #[error("model produced tool-call arguments that are not valid JSON: {source}. raw arguments: {raw:?}.")]
    BadArguments {
        raw: String,
        #[source]
        source: serde_json::Error,
    },

    /// The model produced output that did not validate against the schema after every retry.
    #[error("model output failed schema validation after {attempts} attempt(s). last error: {last_error}. iterate the prompt or relax the schema.")]
    SchemaInvalid { attempts: u32, last_error: String },

    /// The schema passed by the caller did not compile.
    #[error("provided JSON Schema did not compile: {detail}. validate the schema with `jq` and a schema linter.")]
    BadSchema { detail: String },

    /// A local file (audio or image fixture) could not be read.
    #[error("io failure for {path}: {detail}: {source}")]
    Io {
        path: String,
        detail: String,
        #[source]
        source: std::io::Error,
    },

    /// The model returned a string that could not be parsed as the expected
    /// verdict literal. The raw output is preserved for the caller to log.
    #[error(
        "verdict pass did not return a recognised label: {detail}. raw model content: {raw:?}."
    )]
    BadVerdict { raw: String, detail: String },

    /// The sidecar returned more bytes than the per-response cap allows. A
    /// legitimate Gemma 4 chat completion fits in under 100 KB; anything past
    /// the cap indicates a misbehaving or compromised sidecar.
    #[error(
        "sidecar response from {endpoint} exceeded the response-size cap of {cap_bytes} bytes (seen {seen_bytes} bytes). \
         a runaway or compromised sidecar can OOM the capture process; aborting before the body is materialized."
    )]
    ResponseTooLarge {
        endpoint: String,
        cap_bytes: usize,
        seen_bytes: usize,
    },

    /// The configured endpoint is not a loopback address. The capture app is
    /// offline-only; calling a non-loopback host would defeat that guarantee
    /// and ship audio/image content to whatever responded.
    #[error(
        "sidecar endpoint {endpoint:?} is not loopback. only http://127.0.0.1, http://[::1], and unix:// endpoints are permitted; \
         the capture app must remain offline and trust only a local process."
    )]
    EndpointNotLoopback { endpoint: String },

    /// The /v1/handshake nonce echo did not match. The local sidecar either
    /// is not configured with the per-launch shared secret or is not the
    /// process the capture app expects.
    #[error(
        "sidecar handshake at {endpoint} failed: {detail}. \
         restart the app so a fresh token is issued, and confirm no other process is bound to the sidecar port."
    )]
    HandshakeFailed { endpoint: String, detail: String },
}
