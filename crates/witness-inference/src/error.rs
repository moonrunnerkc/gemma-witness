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
}
