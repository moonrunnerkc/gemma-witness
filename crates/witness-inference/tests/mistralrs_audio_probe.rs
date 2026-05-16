//! Contract probe: confirm the mistral.rs sidecar accepts an OpenAI-standard
//! `input_audio` content part and that the model's response is actually
//! conditioned on the audio bytes (i.e. mistral.rs did not silently fall back
//! to text-only inference).
//!
//! The README's "Current limitations" §Audio model behavior previously said
//! "treat as text-conditioned until verified for your version" for
//! mistral.rs. This probe is the verification. When it passes, that caveat is
//! removed in the same PR.
//!
//! Run modes:
//!
//! - `cargo test -p witness-inference --test mistralrs_audio_probe` skips
//!   when the sidecar is not reachable so a default workspace test run on a
//!   host without mistral.rs installed still passes.
//! - Setting `WITNESS_MISTRALRS_REQUIRE=1` flips the skip path into a hard
//!   failure. The release workflow sets this so the v0.2+ release gate
//!   cannot pass without a working audio path.
//! - `WITNESS_MISTRALRS_URL` overrides the default endpoint
//!   `http://127.0.0.1:8080`.
//! - `WITNESS_MISTRALRS_MODEL` overrides the model name sent in the request
//!   body. Default: `google/gemma-4-E4B-it`, matching
//!   `inference/mistralrs-sidecar/start.sh`.
//!
//! Assertion is intentionally loose to respect the non-determinism invariant
//! in CLAUDE.md: the probe passes if the response text contains at least one
//! distinctive keyword from the known transcript. A text-only fallback would
//! produce a generic refusal or hallucination and would not name
//! "construction", "concrete", "rebar", or "workers".

use std::path::PathBuf;
use std::time::Duration;

use base64::Engine;
use serde_json::{json, Value};

const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:8080";
const DEFAULT_MODEL: &str = "google/gemma-4-E4B-it";
const FIXTURE_REL_PATH: &str = "../../tests/fixtures/day-3-scenarios/1/audio.wav";
const PROMPT: &str =
    "Transcribe this audio verbatim. Output only the transcript text, no labels or quotes.";

/// Keywords expected to appear in any reasonable transcription of
/// `tests/fixtures/day-3-scenarios/1/audio.wav`. The probe asserts at least
/// one match (lowercased) is present. Single-word matches are robust to
/// small ASR variations.
const EXPECTED_KEYWORDS: &[&str] = &[
    "concrete",
    "construction",
    "rebar",
    "workers",
    "excavator",
    "site",
];

fn endpoint() -> String {
    std::env::var("WITNESS_MISTRALRS_URL").unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string())
}

fn model_name() -> String {
    std::env::var("WITNESS_MISTRALRS_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.to_string())
}

fn require_mode() -> bool {
    matches!(
        std::env::var("WITNESS_MISTRALRS_REQUIRE").as_deref(),
        Ok("1") | Ok("true")
    )
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_REL_PATH)
}

fn sidecar_reachable(endpoint: &str) -> bool {
    let Ok(client) = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
    else {
        return false;
    };
    client
        .get(format!("{endpoint}/v1/models"))
        .send()
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

fn skip_or_fail(reason: &str) {
    if require_mode() {
        panic!(
            "WITNESS_MISTRALRS_REQUIRE=1 but mistral.rs audio probe could not run: {reason}. \
             this release gate refuses to pass without a working audio path."
        );
    }
    eprintln!(
        "mistralrs_audio_probe: skipping ({reason}). set WITNESS_MISTRALRS_REQUIRE=1 to make this a hard failure."
    );
}

#[test]
fn mistralrs_accepts_input_audio_and_response_is_acoustically_informed() {
    let endpoint = endpoint();
    if !sidecar_reachable(&endpoint) {
        skip_or_fail(&format!(
            "no sidecar reachable at {endpoint}. start one via inference/mistralrs-sidecar/start.sh"
        ));
        return;
    }

    let fixture = fixture_path();
    let audio_bytes = std::fs::read(&fixture).unwrap_or_else(|err| {
        panic!(
            "could not read fixture {}: {err}. confirm tests/fixtures/day-3-scenarios/1/audio.wav is present.",
            fixture.display()
        )
    });
    let audio_b64 = base64::engine::general_purpose::STANDARD.encode(&audio_bytes);

    let body = json!({
        "model": model_name(),
        "max_tokens": 500,
        "temperature": 0.0,
        "messages": [
            {
                "role": "user",
                "content": [
                    { "type": "input_text", "text": PROMPT },
                    {
                        "type": "input_audio",
                        "input_audio": {
                            "data": audio_b64,
                            "format": "wav"
                        }
                    }
                ]
            }
        ]
    });

    let url = format!("{endpoint}/v1/chat/completions");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .expect("build http client");
    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .unwrap_or_else(|err| panic!("POST {url}: {err}"));
    let status = resp.status();
    let text = resp.text().unwrap_or_default();
    assert!(
        status.is_success(),
        "mistral.rs returned non-2xx for input_audio request: status={status} body={}",
        text.chars().take(500).collect::<String>()
    );

    let payload: Value = serde_json::from_str(&text)
        .unwrap_or_else(|err| panic!("mistral.rs response was not valid JSON: {err}; body={text}"));
    let content = payload
        .pointer("/choices/0/message/content")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!("mistral.rs response missing choices[0].message.content. full body: {text}")
        });

    let lowered = content.to_lowercase();
    let hit = EXPECTED_KEYWORDS.iter().find(|kw| lowered.contains(*kw));
    assert!(
        hit.is_some(),
        "mistral.rs response did not contain any expected acoustic keyword \
         (looked for {EXPECTED_KEYWORDS:?}). this strongly suggests mistral.rs \
         silently treated the request as text-only, ignoring the input_audio part. \
         response was: {content:?}"
    );

    eprintln!(
        "mistralrs_audio_probe: PASS (matched keyword {:?}; response length {} chars)",
        hit.unwrap(),
        content.len()
    );
}
