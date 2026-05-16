//! RFC 8785 JSON Canonicalization Scheme helpers.
//!
//! Every signing operation in this crate goes through [`canonicalize`] so
//! that the signature is over a deterministic byte sequence. The matching
//! JS verifier produces the same bytes from the same logical manifest.
//!
//! Before handing the value to `serde_jcs`, integers whose magnitude exceeds
//! 2^53 are projected onto their IEEE 754 double-precision representation.
//! RFC 8785 §3.2.2.3 specifies ECMAScript ToString on a JSON-compatible
//! double-precision value, and JavaScript JSON parsers already collapse
//! large integers to doubles on input. Without this projection a Rust
//! signer that emitted, say, the i64 value 9007199254740993 would produce
//! canonical bytes the JS verifier could never reproduce (the JS side
//! rounds to 9007199254740992 before stringifying). The witness manifest
//! schema does not use integers above 2^53 today, so the projection is a
//! defensive guarantee against future fields slipping into that range.

use serde::Serialize;
use serde_json::{Number, Value};

use crate::error::WitnessCoreError;

const MAX_SAFE_INTEGER: i64 = 1i64 << 53;

/// Canonicalize `value` per RFC 8785 (JCS) and return the resulting bytes.
///
/// # Errors
/// Returns [`WitnessCoreError::Canonicalize`] if the value cannot be encoded.
/// This is rare in practice (it implies a non-finite float or a map with
/// non-string keys), but never an `unwrap`-grade impossibility.
pub fn canonicalize<T: Serialize>(value: &T) -> Result<Vec<u8>, WitnessCoreError> {
    let mut json_value =
        serde_json::to_value(value).map_err(|source| WitnessCoreError::Canonicalize { source })?;
    project_numbers_to_doubles(&mut json_value);
    serde_jcs::to_vec(&json_value).map_err(|source| WitnessCoreError::Canonicalize { source })
}

/// Walk the JSON tree and rewrite any integer whose magnitude exceeds 2^53
/// to the IEEE 754 double-precision number with the same value. The
/// rewrite is a no-op for values inside the safe-integer range, so the
/// canonical bytes for every existing manifest stay byte-identical.
fn project_numbers_to_doubles(value: &mut Value) {
    match value {
        Value::Number(n) => {
            if let Some(replacement) = double_projection(n) {
                *n = replacement;
            }
        }
        Value::Object(map) => {
            for inner in map.values_mut() {
                project_numbers_to_doubles(inner);
            }
        }
        Value::Array(arr) => {
            for inner in arr.iter_mut() {
                project_numbers_to_doubles(inner);
            }
        }
        Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
}

fn double_projection(n: &Number) -> Option<Number> {
    if let Some(i) = n.as_i64() {
        if i.abs() > MAX_SAFE_INTEGER {
            return Number::from_f64(i as f64);
        }
    }
    if let Some(u) = n.as_u64() {
        if u > MAX_SAFE_INTEGER as u64 {
            return Number::from_f64(u as f64);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_integers_pass_through_unchanged() {
        let mut value: Value = serde_json::json!({"a": 1, "b": -100, "c": 9007199254740992_i64});
        let before = value.clone();
        project_numbers_to_doubles(&mut value);
        assert_eq!(value, before);
    }

    #[test]
    fn integer_above_two_pow_53_rounds_to_double() {
        let mut value: Value = serde_json::json!({"a": 9007199254740993_i64});
        project_numbers_to_doubles(&mut value);
        // 9007199254740993 (2^53 + 1) cannot be represented exactly in f64;
        // it rounds to 9007199254740992 (2^53). Both Rust and JS now emit
        // the same canonical bytes.
        let bytes = serde_jcs::to_vec(&value).expect("canonicalize");
        assert_eq!(bytes, br#"{"a":9007199254740992}"#);
    }

    #[test]
    fn negative_integer_below_minus_two_pow_53_rounds_to_double() {
        let mut value: Value = serde_json::json!({"a": -9007199254740993_i64});
        project_numbers_to_doubles(&mut value);
        let bytes = serde_jcs::to_vec(&value).expect("canonicalize");
        assert_eq!(bytes, br#"{"a":-9007199254740992}"#);
    }

    #[test]
    fn rewrite_walks_into_objects_and_arrays() {
        let mut value: Value = serde_json::json!({
            "outer": [{"inner": 18014398509481985_i64}],
        });
        project_numbers_to_doubles(&mut value);
        let bytes = serde_jcs::to_vec(&value).expect("canonicalize");
        // 2^54 + 1 rounds to 2^54.
        assert_eq!(bytes, br#"{"outer":[{"inner":18014398509481984}]}"#);
    }
}
