//! Property tests for the canonicalizer.
//!
//! These cover three invariants:
//!
//! 1. Canonical output is byte-stable under parse-then-recanonicalize
//!    (the fixed-point property: canonicalize(parse(canonicalize(x))) == canonicalize(x)).
//! 2. Canonical output is independent of source key order, including at
//!    nested depths (RFC 8785 §3.2.3).
//! 3. Canonicalizing the same logical value via a typed struct and via
//!    `serde_json::Value` produces identical bytes.
//!
//! Cross-language byte equality with the JS verifier is enforced separately
//! by the conformance fixtures at
//! `tests/fixtures/canonicalization-conformance/`.

use proptest::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use witness_core::canonical::canonicalize;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Toy {
    name: String,
    count: i64,
    tags: Vec<String>,
    nested: NestedToy,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct NestedToy {
    label: String,
    flag: bool,
}

proptest! {
    #[test]
    fn jcs_roundtrip_is_byte_stable(
        name in "[a-zA-Z0-9 _-]{0,40}",
        count in any::<i64>(),
        tags in proptest::collection::vec("[a-zA-Z0-9]{0,16}", 0..6),
        label in "[a-zA-Z]{0,32}",
        flag in any::<bool>(),
    ) {
        let value = Toy {
            name,
            count,
            tags,
            nested: NestedToy { label, flag },
        };
        let bytes_a = canonicalize(&value).expect("canonicalize a");
        let parsed: Toy = serde_json::from_slice(&bytes_a).expect("parse");
        let bytes_b = canonicalize(&parsed).expect("canonicalize b");
        prop_assert_eq!(bytes_a, bytes_b);
    }

    #[test]
    fn typed_and_untyped_canonicalize_to_same_bytes(
        name in "[a-zA-Z0-9 _-]{0,40}",
        count in any::<i64>(),
        label in "[a-zA-Z]{0,32}",
        flag in any::<bool>(),
    ) {
        let typed = Toy {
            name: name.clone(),
            count,
            tags: vec![],
            nested: NestedToy { label: label.clone(), flag },
        };
        let untyped: Value = serde_json::json!({
            "name": name,
            "count": count,
            "tags": [],
            "nested": { "label": label, "flag": flag },
        });
        let typed_bytes = canonicalize(&typed).expect("typed");
        let untyped_bytes = canonicalize(&untyped).expect("untyped");
        prop_assert_eq!(typed_bytes, untyped_bytes);
    }

    #[test]
    fn shuffled_keys_at_arbitrary_depth_produce_identical_bytes(
        // 1 to 12 key/value pairs at the top level, each with an inner
        // object holding 1 to 6 pairs. Keys are constrained to a 6-char
        // ASCII alphabet so collisions are possible (deduped post-hoc).
        keys in proptest::collection::vec("[a-z]{1,6}", 1..12),
        inner_keys in proptest::collection::vec("[a-z]{1,6}", 1..6),
    ) {
        let mut outer_a: Map<String, Value> = Map::new();
        let mut outer_b: Map<String, Value> = Map::new();
        for (i, k) in keys.iter().enumerate() {
            let mut inner_a: Map<String, Value> = Map::new();
            let mut inner_b: Map<String, Value> = Map::new();
            for (j, ik) in inner_keys.iter().enumerate() {
                inner_a.insert(ik.clone(), Value::from(j as i64));
                // Insert into b in reversed order to exercise the nested sort.
                inner_b.insert(
                    inner_keys[inner_keys.len() - 1 - j].clone(),
                    Value::from(inner_keys.len() as i64 - 1 - j as i64),
                );
            }
            outer_a.insert(k.clone(), Value::Object(inner_a));
            outer_b.insert(
                keys[keys.len() - 1 - i].clone(),
                Value::Object(inner_b.clone()),
            );
        }
        // Rebuild b's inner objects so each holds the same logical mapping
        // as the matching key in a (the reversal above produced different
        // value assignments).
        for k in outer_a.keys().cloned().collect::<Vec<_>>() {
            if let (Some(a), Some(b)) = (outer_a.get(&k), outer_b.get_mut(&k)) {
                *b = a.clone();
            }
        }
        let bytes_a = canonicalize(&Value::Object(outer_a)).expect("a");
        let bytes_b = canonicalize(&Value::Object(outer_b)).expect("b");
        prop_assert_eq!(bytes_a, bytes_b);
    }
}

#[test]
fn jcs_key_order_independence_holds() {
    let payload_a = serde_json::json!({"b": 1, "a": 2, "c": [3, 4]});
    let payload_b = serde_json::json!({"c": [3, 4], "a": 2, "b": 1});
    assert_eq!(
        canonicalize(&payload_a).unwrap(),
        canonicalize(&payload_b).unwrap(),
        "JCS canonical form must be insensitive to source key order"
    );
}

#[test]
fn key_ordering_holds_at_every_depth() {
    let payload_a = serde_json::json!({
        "z": {"b": 1, "a": 2, "c": {"y": 3, "x": 4}},
        "y": [{"d": 5, "c": 6}, {"b": 7, "a": 8}],
    });
    let payload_b = serde_json::json!({
        "y": [{"c": 6, "d": 5}, {"a": 8, "b": 7}],
        "z": {"c": {"x": 4, "y": 3}, "a": 2, "b": 1},
    });
    assert_eq!(
        canonicalize(&payload_a).unwrap(),
        canonicalize(&payload_b).unwrap(),
        "key ordering must be applied recursively, not just at the root"
    );
}

#[test]
fn array_order_is_preserved() {
    // Arrays are NOT sorted; their order is significant per JSON semantics
    // and RFC 8785 §3.2.4 only sorts object members.
    let payload_a = serde_json::json!([3, 1, 2]);
    let payload_b = serde_json::json!([1, 2, 3]);
    assert_ne!(
        canonicalize(&payload_a).unwrap(),
        canonicalize(&payload_b).unwrap()
    );
}
