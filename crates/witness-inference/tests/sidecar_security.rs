//! Regression tests for the sidecar trust-boundary hardening landed under
//! audit findings T-7 (token), I-1 (response-size cap), and I-3 (loopback).

use std::sync::LazyLock;

use tokio::sync::Mutex;
use witness_inference::{
    assert_endpoint_is_loopback, fetch_active_model_id_default, handshake, InferenceError,
};
use witness_test_sidecar::{start, FakeConfig};

static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[test]
fn with_endpoint_rejects_non_loopback_url() {
    // I-3: only loopback http addresses are accepted.
    let err = assert_endpoint_is_loopback("http://example.com:8080")
        .expect_err("non-loopback endpoint must be rejected");
    assert!(matches!(err, InferenceError::EndpointNotLoopback { .. }));

    assert!(assert_endpoint_is_loopback("http://127.0.0.1:8080").is_ok());
    assert!(assert_endpoint_is_loopback("http://[::1]:8080").is_ok());
    assert!(assert_endpoint_is_loopback("unix:///tmp/sidecar.sock").is_ok());
}

#[tokio::test]
async fn fetch_active_model_id_with_correct_token_succeeds() {
    let _env_guard = ENV_LOCK.lock().await;
    let cfg = FakeConfig {
        required_token: Some("test-token-deadbeef".to_string()),
        ..FakeConfig::default()
    };
    let server = start(cfg).await.expect("start fake sidecar");

    let prev = std::env::var("GW_SIDECAR_TOKEN").ok();
    std::env::set_var("GW_SIDECAR_TOKEN", "test-token-deadbeef");
    let result = fetch_active_model_id_default(&server.endpoint).await;
    if let Some(prev) = prev {
        std::env::set_var("GW_SIDECAR_TOKEN", prev);
    } else {
        std::env::remove_var("GW_SIDECAR_TOKEN");
    }
    server.shutdown().await;

    let id = result.expect("authenticated call must succeed");
    assert_eq!(id, "mlx-community/gemma-4-e4b-it-4bit");
}

#[tokio::test]
async fn fetch_active_model_id_prefers_default_when_sidecar_lists_cached_models() {
    let _env_guard = ENV_LOCK.lock().await;
    let cfg = FakeConfig {
        listed_model_ids: Some(vec![
            "mlx-community/Qwen3.6-35B-A3B-8bit".to_string(),
            "mlx-community/gemma-4-e4b-it-4bit".to_string(),
        ]),
        ..FakeConfig::default()
    };
    let server = start(cfg).await.expect("start fake sidecar");

    let prev_model = std::env::var("GW_SIDECAR_MODEL").ok();
    std::env::remove_var("GW_SIDECAR_MODEL");
    let result = fetch_active_model_id_default(&server.endpoint).await;
    if let Some(prev) = prev_model {
        std::env::set_var("GW_SIDECAR_MODEL", prev);
    }
    server.shutdown().await;

    let id = result.expect("default Gemma model should be selected from model list");
    assert_eq!(id, "mlx-community/gemma-4-e4b-it-4bit");
}

#[tokio::test]
async fn fetch_active_model_id_without_token_returns_unauthenticated() {
    let _env_guard = ENV_LOCK.lock().await;
    // T-7: a sidecar configured with required_token rejects unauthenticated
    // callers with 401. The capture app reads this as a typed BadStatus.
    let cfg = FakeConfig {
        required_token: Some("test-token-deadbeef".to_string()),
        ..FakeConfig::default()
    };
    let server = start(cfg).await.expect("start fake sidecar");

    let prev = std::env::var("GW_SIDECAR_TOKEN").ok();
    std::env::remove_var("GW_SIDECAR_TOKEN");
    let result = fetch_active_model_id_default(&server.endpoint).await;
    if let Some(prev) = prev {
        std::env::set_var("GW_SIDECAR_TOKEN", prev);
    }
    server.shutdown().await;

    match result {
        Err(InferenceError::BadStatus { status, .. }) => {
            assert_eq!(
                status, 401,
                "expected sidecar to refuse unauthenticated call"
            );
        }
        other => panic!("expected 401 BadStatus, got {other:?}"),
    }
}

#[tokio::test]
async fn handshake_with_correct_token_round_trips() {
    let _env_guard = ENV_LOCK.lock().await;
    let cfg = FakeConfig {
        required_token: Some("hs-token-abc".to_string()),
        ..FakeConfig::default()
    };
    let server = start(cfg).await.expect("start fake sidecar");

    let prev = std::env::var("GW_SIDECAR_TOKEN").ok();
    std::env::set_var("GW_SIDECAR_TOKEN", "hs-token-abc");
    let client = reqwest::Client::builder().build().unwrap();
    let result = handshake(&client, &server.endpoint).await;
    if let Some(prev) = prev {
        std::env::set_var("GW_SIDECAR_TOKEN", prev);
    } else {
        std::env::remove_var("GW_SIDECAR_TOKEN");
    }
    server.shutdown().await;

    result.expect("authenticated handshake must succeed");
}

#[tokio::test]
async fn handshake_without_token_fails_closed() {
    let _env_guard = ENV_LOCK.lock().await;
    let cfg = FakeConfig {
        required_token: Some("hs-token-abc".to_string()),
        ..FakeConfig::default()
    };
    let server = start(cfg).await.expect("start fake sidecar");

    let prev = std::env::var("GW_SIDECAR_TOKEN").ok();
    std::env::remove_var("GW_SIDECAR_TOKEN");
    let client = reqwest::Client::builder().build().unwrap();
    let result = handshake(&client, &server.endpoint).await;
    if let Some(prev) = prev {
        std::env::set_var("GW_SIDECAR_TOKEN", prev);
    }
    server.shutdown().await;

    match result {
        Err(InferenceError::HandshakeFailed { detail, .. }) => {
            assert!(detail.contains("401"), "expected 401 surface: {detail}");
        }
        other => panic!("expected HandshakeFailed, got {other:?}"),
    }
}

#[tokio::test]
async fn fetch_active_model_id_aborts_on_oversized_response() {
    // I-1: cap the response body at MAX_RESPONSE_BYTES regardless of what
    // the sidecar reports. The fake sidecar applies the oversize_padding
    // policy to /v1/chat/completions, so we exercise the cap via the chat
    // path. /v1/models is not padded; build a tiny fake that pads chat.
    use witness_inference::{InferenceClient, MAX_RESPONSE_BYTES};

    let cfg = FakeConfig {
        oversized_response_bytes: Some(MAX_RESPONSE_BYTES + 1024),
        ..FakeConfig::default()
    };
    let server = start(cfg).await.expect("start fake sidecar");

    let client =
        InferenceClient::with_endpoint(&server.endpoint).expect("client builds against loopback");

    let schema = serde_json::json!({
        "type": "object",
        "required": ["timestamp", "location", "incident_type", "narrative_summary", "severity", "evidence_references"],
        "properties": {
            "timestamp": {"type":"string"},
            "location": {"type":"object","required":["description"],"properties":{"description":{"type":"string"}}},
            "incident_type": {"type":"string"},
            "narrative_summary": {"type":"string","minLength": 1},
            "severity": {"type":"integer"},
            "evidence_references": {"type":"array"}
        }
    });
    let result = client.structure_incident("hello", &schema).await;
    server.shutdown().await;

    match result {
        Err(InferenceError::ResponseTooLarge {
            cap_bytes,
            seen_bytes,
            ..
        }) => {
            assert_eq!(cap_bytes, MAX_RESPONSE_BYTES);
            assert!(
                seen_bytes > MAX_RESPONSE_BYTES,
                "seen_bytes ({seen_bytes}) must exceed cap"
            );
        }
        Err(other) => panic!("expected ResponseTooLarge, got {other:?}"),
        Ok(outcome) => panic!("oversized response was not rejected: {outcome:?}"),
    }
}
