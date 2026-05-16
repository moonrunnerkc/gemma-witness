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
use witness_core::canonical::canonicalize;

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
    // Route through the project's own wrapper so the conformance suite
    // exercises the same code path production signing does, including the
    // integer-to-double projection that aligns Rust output with JavaScript.
    let computed = canonicalize(&value).expect("canonicalize");

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

// ----------------------------------------------------------------------------
// Expanded edge cases. Each documents a specific RFC 8785 surface where the
// Rust and JS canonicalizers must agree byte-for-byte; a divergence here is
// what the test is designed to catch.
// ----------------------------------------------------------------------------

#[test]
fn case_negative_zero() {
    // ECMAScript ToString(-0) == "0". RFC 8785 §3.2.2.3 requires this
    // collapse. Both libraries must emit `"a":0`, not `"a":-0`.
    assert_case("negative-zero", r#"{"a":-0.0}"#);
}

#[test]
fn case_subnormal_float() {
    // 5e-324 is the smallest positive IEEE 754 double-precision subnormal.
    // RFC 8785 §3.2.2.3 specifies ECMAScript ToString, which emits
    // "5e-324" for this value. Recorded so any library drift surfaces here.
    assert_case("subnormal-float", r#"{"a":5e-324}"#);
}

#[test]
fn case_integer_cliff_exact_doubles() {
    // Three values above the 2^53 safe-integer boundary that ARE exactly
    // representable as IEEE 754 doubles:
    //   2^53 + 2   = 9007199254740994     (even, exact)
    //   2^54       = 18014398509481984    (power of two, exact)
    //   -(2^53)    = -9007199254740992    (exact)
    // Both libraries emit the input literally.
    assert_case(
        "integer-cliff-exact-doubles",
        r#"{"a":9007199254740994,"b":18014398509481984,"c":-9007199254740992}"#,
    );
}

#[test]
fn case_integer_precision_loss_projection() {
    // Three values straddling the 2^53 safe-integer boundary that are NOT
    // exactly representable in IEEE 754 double precision:
    //   2^53 + 1 = 9007199254740993        rounds to 2^53     (9007199254740992)
    //   2^54 + 1 = 18014398509481985       rounds to 2^54     (18014398509481984)
    //   -(2^53 + 1) = -9007199254740993    rounds to -2^53    (-9007199254740992)
    //
    // RFC 8785 §3.2.2.3 specifies ECMAScript ToString applied to a
    // double-precision value, so JavaScript verifiers round on input. The
    // witness-core `canonicalize` wrapper projects these onto their double
    // representation before serde_jcs runs, keeping Rust's output
    // byte-identical to the JS side. Without the projection the two sides
    // diverge and a signed manifest produced on Rust would be rejected by
    // the static-HTML verifier.
    assert_case(
        "integer-precision-loss-projection",
        r#"{"a":9007199254740993,"b":18014398509481985,"c":-9007199254740993}"#,
    );
}

#[test]
fn case_empty_key() {
    // The empty string is a legal JSON key. Both libraries must emit
    // `"":"v"` (key first by lexicographic order against any non-empty key).
    assert_case("empty-key", r#"{"":"v","k":""}"#);
}

#[test]
fn case_long_string() {
    // 1024-character ASCII string. Catches any chunked-output bug where a
    // library writes the string in pieces and a boundary appears in a
    // surprising place.
    let body = "x".repeat(1024);
    let input = format!(r#"{{"k":"{body}"}}"#);
    assert_case("long-string", &input);
}

#[test]
fn case_control_characters() {
    // 0x00-0x1F. RFC 8785 says short escapes (\b \t \n \f \r) for the five
    // values that have them, \u00XX otherwise. Both libraries must pick the
    // same form for each byte.
    let mut buf = String::from("{\"k\":\"");
    for byte in 0u8..=0x1F {
        // We pass the raw escape form to serde_json; it parses to the actual
        // control character internally, and the canonicalizer re-emits it in
        // the form RFC 8785 mandates.
        buf.push_str(&format!("\\u{byte:04x}"));
    }
    buf.push_str("\"}");
    assert_case("control-characters", &buf);
}

#[test]
fn case_combining_diacritic() {
    // U+0301 (combining acute) following an ASCII letter. The canonical
    // form must escape the combining mark as ́; the canonicalizer
    // must not normalize (NFC/NFD), per RFC 8785's pass-through rule.
    let input = "{\"k\":\"a\u{0301}\"}";
    assert_case("combining-diacritic", input);
}

#[test]
fn case_rtl_mark() {
    // U+200F (right-to-left mark). Bidirectional formatting characters
    // must be preserved verbatim and escaped per RFC 8785.
    let input = "{\"k\":\"a\u{200F}b\"}";
    assert_case("rtl-mark", input);
}

#[test]
fn case_zwj_emoji_sequence() {
    // Woman technologist: U+1F469 ZWJ U+1F4BB. Two non-BMP code points
    // joined by U+200D. Tests surrogate-pair encoding plus the zero-width
    // joiner in the same string.
    let input = "{\"k\":\"\u{1F469}\u{200D}\u{1F4BB}\"}";
    assert_case("zwj-emoji-sequence", input);
}

#[test]
fn case_many_keys_lexicographic() {
    // 256 keys with names that would not sort the same under insertion
    // order as under codepoint order. Both libraries must emit them sorted.
    let mut keys: Vec<String> = (0..256).map(|i| format!("k{i:03}")).collect();
    // Shuffle the input order (deterministically) by reversing.
    keys.reverse();
    let pairs: Vec<String> = keys.iter().map(|k| format!("\"{k}\":1")).collect();
    let input = format!("{{{}}}", pairs.join(","));
    assert_case("many-keys-lexicographic", &input);
}

#[test]
fn case_mixed_nested_collections() {
    // Arrays in objects in arrays in objects. Catches recursion-order bugs
    // where a library sorts at one depth but not another.
    assert_case(
        "mixed-nested-collections",
        r#"{"outer":[{"b":[3,2,1],"a":[{"z":1,"y":2}]}]}"#,
    );
}

#[test]
fn case_numeric_notation_normalization() {
    // 100, 1e2, 1.0e+02, and 100.0 are all the same IEEE 754 double. The
    // canonical form must collapse them to "100" (ECMAScript ToString),
    // making all four key-value pairs textually identical post-canonicalize.
    assert_case(
        "numeric-notation-normalization",
        r#"{"a":100,"b":1e2,"c":1.0e+02,"d":100.0}"#,
    );
}

#[test]
fn case_key_ordering_at_depth() {
    // At every depth, keys must sort. Catches a bug where a library sorts
    // top-level keys but leaves inner objects in insertion order.
    assert_case(
        "key-ordering-at-depth",
        r#"{"z":{"b":1,"a":2},"y":{"d":3,"c":4},"x":{"f":5,"e":6}}"#,
    );
}

#[test]
fn case_deep_nesting_15_levels() {
    // 15 levels deep. Catches stack-depth or recursion-limit issues that
    // would not appear at the existing 7-level fixture.
    let mut input = String::from("1");
    for _ in 0..15 {
        input = format!("{{\"k\":{input}}}");
    }
    assert_case("deep-nesting-15-levels", &input);
}
