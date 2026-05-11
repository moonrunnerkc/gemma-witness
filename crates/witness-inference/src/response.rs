//! Parsing helpers for the OpenAI-compatible chat-completions response shape.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::InferenceError;

/// Tool name advertised to the model.
pub(crate) const TOOL_NAME: &str = "record_incident";

#[derive(Debug, Deserialize, Serialize)]
struct ChatChoice {
    message: ChatMessage,
}

#[derive(Debug, Deserialize, Serialize)]
struct ChatMessage {
    #[serde(default)]
    tool_calls: Option<Vec<ToolCall>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ToolCall {
    function: ToolFunction,
}

#[derive(Debug, Deserialize, Serialize)]
struct ToolFunction {
    name: String,
    arguments: String,
}

/// Pull the `arguments` JSON string out of the first tool call, validating
/// the call's function name matches [`TOOL_NAME`].
pub(crate) fn extract_tool_arguments(payload: &Value) -> Result<String, InferenceError> {
    let choices = payload
        .get("choices")
        .and_then(|v| v.as_array())
        .ok_or_else(|| InferenceError::BadShape {
            field: "choices".to_string(),
            detail: "missing or not an array".to_string(),
        })?;
    let first = choices.first().ok_or_else(|| InferenceError::BadShape {
        field: "choices[0]".to_string(),
        detail: "empty choices array".to_string(),
    })?;
    let parsed: ChatChoice =
        serde_json::from_value(first.clone()).map_err(|source| InferenceError::BadShape {
            field: "choices[0]".to_string(),
            detail: format!("did not match expected shape: {source}"),
        })?;
    let calls = parsed
        .message
        .tool_calls
        .ok_or_else(|| InferenceError::BadShape {
            field: "choices[0].message.tool_calls".to_string(),
            detail: "model returned no tool call (try lowering temperature or stiffening prompt)"
                .to_string(),
        })?;
    let call = calls
        .into_iter()
        .next()
        .ok_or_else(|| InferenceError::BadShape {
            field: "choices[0].message.tool_calls[0]".to_string(),
            detail: "tool_calls array was empty".to_string(),
        })?;
    if call.function.name != TOOL_NAME {
        return Err(InferenceError::BadShape {
            field: "choices[0].message.tool_calls[0].function.name".to_string(),
            detail: format!("expected {TOOL_NAME}, got {}", call.function.name),
        });
    }
    Ok(call.function.arguments)
}
