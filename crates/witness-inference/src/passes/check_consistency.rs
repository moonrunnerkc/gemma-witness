//! Pass 3: audio/image consistency verdict.
//!
//! Takes the structured incident report (pass 1), the transcript, and the
//! per-image descriptions (pass 2), asks Gemma 4 to decide whether the audio
//! narrative and the image evidence agree, and captures the model's
//! thinking-channel output verbatim.
//!
//! Thinking mode is enabled by prepending `<|think|>` to the system prompt,
//! as documented in `build-guide.md` and confirmed against the running
//! mlx-vlm sidecar on 2026-05-10: the server returns the raw chain-of-thought
//! in `choices[0].message.reasoning` whenever the system prompt begins with
//! that sentinel.

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use witness_core::IncidentReport;

use crate::error::InferenceError;
use crate::http::{
    build_http_client, extract_reasoning, extract_text_content, post_chat, DEFAULT_MODEL,
};

const DEFAULT_MAX_TOKENS: u32 = 1200;
const DEFAULT_TEMPERATURE: f32 = 0.2;

const SYSTEM_PROMPT: &str = "<|think|>You are a careful evidence reviewer. \
You are given a transcript of an audio recording, a structured incident report extracted from it, \
and short descriptions of one or more images submitted alongside the audio. \
Decide whether the image descriptions are consistent with what the audio narrative claims. \
Think step by step. Do not invent facts. \
Then answer by emitting a single JSON object with exactly two keys: \
`verdict` (one of `consistent`, `partially-consistent`, `inconsistent`) and \
`reason` (one short sentence, at most 200 characters, explaining the verdict). \
Output the JSON object and nothing else after thinking.";

/// Allowed verdict values, exposed for callers that want to do their own
/// validation or display.
pub const ALLOWED_VERDICTS: [&str; 3] = ["consistent", "partially-consistent", "inconsistent"];

/// Result of the consistency-check pass.
#[derive(Debug, Clone, Serialize)]
pub struct ConsistencyOutcome {
    /// One of [`ALLOWED_VERDICTS`].
    pub verdict: String,
    /// One-sentence explanation produced by the model.
    pub reason: String,
    /// Verbatim thinking-channel content. Stored byte-for-byte as emitted by
    /// the sidecar; never trimmed, summarised, or pretty-printed.
    pub reasoning_trace: String,
    /// SHA-256 of [`Self::reasoning_trace`] bytes. Hex-encoded. The manifest
    /// will eventually sign over this hash.
    pub reasoning_trace_sha256_hex: String,
    /// Wall-clock latency in milliseconds.
    pub latency_ms: u128,
}

#[derive(Debug, Deserialize)]
struct VerdictJson {
    verdict: String,
    reason: String,
}

/// Run pass 3.
///
/// `image_descriptions` is the list of per-image description strings produced
/// by [`crate::passes::analyze_image::analyze_image`], in the order the
/// images were submitted.
///
/// # Errors
///
/// Returns [`InferenceError::BadVerdict`] if the model produced something
/// that is not a recognisable verdict JSON object, plus the usual transport
/// and shape errors.
pub async fn check_consistency(
    transcript: &str,
    report: &IncidentReport,
    image_descriptions: &[String],
    endpoint: &str,
) -> Result<ConsistencyOutcome, InferenceError> {
    let report_json =
        serde_json::to_string_pretty(report).map_err(|source| InferenceError::BadJson {
            body_snippet: "<incident report>".to_string(),
            source,
        })?;
    let user_text = build_user_prompt(transcript, &report_json, image_descriptions);

    let body = json!({
        "model": DEFAULT_MODEL,
        "max_tokens": DEFAULT_MAX_TOKENS,
        "temperature": DEFAULT_TEMPERATURE,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_text}
        ]
    });

    let http = build_http_client(endpoint)?;
    let started = std::time::Instant::now();
    let payload = post_chat(&http, endpoint, &body).await?;
    let reasoning_trace = extract_reasoning(&payload)?;
    let raw_content = extract_text_content(&payload).unwrap_or_default();
    let (verdict, reason) = parse_verdict(&raw_content, &reasoning_trace)?;
    let reasoning_trace_sha256_hex = hex::encode(Sha256::digest(reasoning_trace.as_bytes()));

    Ok(ConsistencyOutcome {
        verdict,
        reason,
        reasoning_trace,
        reasoning_trace_sha256_hex,
        latency_ms: started.elapsed().as_millis(),
    })
}

fn build_user_prompt(transcript: &str, report_json: &str, descriptions: &[String]) -> String {
    let mut images_section = String::new();
    if descriptions.is_empty() {
        images_section.push_str("(no images submitted)\n");
    } else {
        for (index, description) in descriptions.iter().enumerate() {
            images_section.push_str(&format!("Image {}: {}\n", index + 1, description.trim()));
        }
    }
    format!(
        "<transcript>\n{transcript}\n</transcript>\n\n\
<incident_report>\n{report_json}\n</incident_report>\n\n\
<image_descriptions>\n{images_section}</image_descriptions>\n\n\
Decide whether the image descriptions are consistent with the transcript and the incident report. \
Output the JSON verdict object now."
    )
}

fn parse_verdict(content: &str, reasoning: &str) -> Result<(String, String), InferenceError> {
    let object_text = locate_json_object(content)
        .or_else(|| locate_last_json_object(reasoning))
        .ok_or_else(|| InferenceError::BadVerdict {
            raw: if content.is_empty() {
                reasoning.to_string()
            } else {
                content.to_string()
            },
            detail: "no JSON object found in the assistant content or thinking-channel tail. raise max_tokens or harden the system prompt.".to_string(),
        })?;
    let parsed: VerdictJson =
        serde_json::from_str(&object_text).map_err(|source| InferenceError::BadVerdict {
            raw: object_text.clone(),
            detail: format!("verdict JSON did not parse: {source}"),
        })?;
    let normalized = parsed.verdict.trim().to_ascii_lowercase();
    if !ALLOWED_VERDICTS.contains(&normalized.as_str()) {
        return Err(InferenceError::BadVerdict {
            raw: object_text,
            detail: format!(
                "verdict label `{}` is not one of {:?}",
                parsed.verdict, ALLOWED_VERDICTS
            ),
        });
    }
    Ok((normalized, parsed.reason.trim().to_string()))
}

/// Find the first balanced `{...}` JSON object substring in `text`.
///
/// The model is asked to emit only a JSON object, but it sometimes prepends a
/// stray newline or a markdown fence. Scanning for the first balanced object
/// tolerates that without lowering the schema-level strictness applied next.
fn locate_json_object(text: &str) -> Option<String> {
    locate_json_object_from(text, 0).map(|s| s.to_string())
}

/// Find the LAST balanced `{...}` JSON object substring in `text`. Used to
/// pull the verdict object out of the thinking channel when the model ran
/// out of tokens before emitting the final assistant message.
fn locate_last_json_object(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut last: Option<String> = None;
    let mut cursor = 0;
    while cursor < bytes.len() {
        match locate_json_object_from(text, cursor) {
            Some(found) => {
                let end = (found.as_ptr() as usize - text.as_ptr() as usize) + found.len();
                last = Some(found.to_string());
                cursor = end;
            }
            None => break,
        }
    }
    last
}

fn locate_json_object_from(text: &str, from: usize) -> Option<&str> {
    let bytes = text.as_bytes();
    if from >= bytes.len() {
        return None;
    }
    let start = bytes[from..].iter().position(|b| *b == b'{')? + from;
    let mut depth: i32 = 0;
    let mut in_string = false;
    let mut escape = false;
    for (offset, byte) in bytes[start..].iter().enumerate() {
        if escape {
            escape = false;
            continue;
        }
        match *byte {
            b'\\' if in_string => escape = true,
            b'"' => in_string = !in_string,
            b'{' if !in_string => depth += 1,
            b'}' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return Some(&text[start..=start + offset]);
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{locate_json_object, parse_verdict};

    #[test]
    fn locate_json_object_finds_first_balanced_block() {
        let payload = "prefix {\"verdict\":\"consistent\",\"reason\":\"ok\"} trailing";
        let found = locate_json_object(payload).expect("balanced object present");
        assert_eq!(found, "{\"verdict\":\"consistent\",\"reason\":\"ok\"}");
    }

    #[test]
    fn parse_verdict_rejects_unknown_label() {
        let raw = "{\"verdict\":\"maybe\",\"reason\":\"unclear\"}";
        let err = parse_verdict(raw, "").expect_err("unknown verdict must reject");
        assert!(format!("{err}").contains("not one of"));
    }

    #[test]
    fn parse_verdict_normalises_case_and_whitespace() {
        let raw = "  {\"verdict\":\"Consistent\",\"reason\":\"  fine  \"}  ";
        let (verdict, reason) = parse_verdict(raw, "").expect("verdict parses");
        assert_eq!(verdict, "consistent");
        assert_eq!(reason, "fine");
    }

    #[test]
    fn parse_verdict_falls_back_to_reasoning_tail() {
        let reasoning = "thoughts go here {\"verdict\":\"draft\"} and then\nFinal answer: {\"verdict\":\"inconsistent\",\"reason\":\"images show parking lot, audio describes kitchen\"}";
        let (verdict, reason) = parse_verdict("", reasoning).expect("fallback parses");
        assert_eq!(verdict, "inconsistent");
        assert!(reason.contains("parking"));
    }
}
