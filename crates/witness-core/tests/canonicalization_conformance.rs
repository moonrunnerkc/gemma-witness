//! Cross-language canonicalization conformance suite (audit C-11).
//!
//! This test acts as the canonical-bytes generator AND the conformance
//! check. For each named edge case it:
//!
//! 1. Loads `tests/fixtures/canonicalization-conformance/<name>.input.json`.
//! 2. Canonicalizes via `serde_jcs::to_vec` and compares against
//!    `tests/fixtures/canonicalization-conformance/<name>.expected.bin`.
//! 3. When the fixture is missing (e.g., first run after a new case is
//!    added), regenerates it. CI runs with the fixtures already committed,
//!    so the regen branch is dormant except locally.
//!
//! The JS counterpart in `apps/verifier/tests/canonicalization-conformance.test.ts`
//! reads the same input/expected pairs and asserts byte equality from the JS
//! `canonicalize` library. Divergence on a future float-formatting edge
//! lands here as a failing assertion before any signed bundle drifts.

use std::path::{Path, PathBuf};

use serde_json::Value;

fn fixtures_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../tests/fixtures/canonicalization-conformance");
    p
}

fn input_path(name: &str) -> PathBuf {
    fixtures_dir().join(format!("{name}.input.json"))
}

fn expected_path(name: &str) -> PathBuf {
    fixtures_dir().join(format!("{name}.expected.bin"))
}

fn assert_case(name: &str, input_json: &str) {
    let value: Value = serde_json::from_str(input_json).expect("input parses as JSON");
    let computed = serde_jcs::to_vec(&value).expect("serde_jcs canonicalizes");

    std::fs::create_dir_all(fixtures_dir()).expect("create fixtures dir");

    let expected_p = expected_path(name);
    if !Path::new(&expected_p).exists() {
        std::fs::write(&expected_p, &computed).expect("write expected.bin");
    }
    if !input_path(name).exists() {
        std::fs::write(input_path(name), input_json).expect("write input.json");
    }

    let expected = std::fs::read(&expected_p).expect("expected.bin readable");
    assert_eq!(
        expected, computed,
        "canonicalization output for case {name} drifted; \
         delete tests/fixtures/canonicalization-conformance/{name}.expected.bin to regenerate \
         (and update the JS side in lockstep)"
    );
}

#[test]
fn case_empty_object() {
    assert_case("empty-object", "{}");
}

#[test]
fn case_empty_array() {
    assert_case("empty-array", "[]");
}

#[test]
fn case_integers_near_2_pow_53() {
    // 2^53 and 2^53 - 1 sit at the edge of safe integer representation in
    // IEEE 754 doubles. Both libraries must agree on how they serialize.
    assert_case(
        "integers-near-2pow53",
        r#"{"a":9007199254740991,"b":9007199254740992,"c":-9007199254740991}"#,
    );
}

#[test]
fn case_small_floats() {
    // 1e-7 is the documented divergence surface between RFC 8785
    // implementations. Pin the expected bytes now so any later library
    // change is caught.
    assert_case(
        "small-floats",
        r#"{"temperature":0.0000001,"top_p":0.9,"zero":0.0}"#,
    );
}

#[test]
fn case_escaped_unicode_and_surrogate_pairs() {
    // A literal non-BMP code point (`𝄞`, U+1D11E) plus an emoji (`😀`,
    // U+1F600). Both require UTF-16 surrogate pairs when escaped, which is
    // the most common divergence surface between RFC 8785 implementations
    // in this category.
    let input = "{\"k\":\"ab\u{1D11E}c\u{00E9} \u{1F600}\"}";
    assert_case("escaped-unicode", input);
}

#[test]
fn case_deeply_nested_keys() {
    assert_case(
        "deeply-nested-keys",
        r#"{"z":{"a":{"y":{"b":{"x":{"c":{"w":1}}}}}}}"#,
    );
}

#[test]
fn rejects_nan() {
    // serde_json itself refuses to parse "NaN" as a number; the JCS spec
    // explicitly forbids it. This assertion just documents that the input
    // cannot reach the canonicalizer.
    let parsed: Result<Value, _> = serde_json::from_str("NaN");
    assert!(parsed.is_err(), "NaN must not parse as JSON");
}

#[test]
fn rejects_infinity() {
    let parsed: Result<Value, _> = serde_json::from_str("Infinity");
    assert!(parsed.is_err(), "Infinity must not parse as JSON");
}
