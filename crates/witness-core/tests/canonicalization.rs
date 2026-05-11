//! Property test: serialize, parse, re-serialize, bytes equal.

use proptest::prelude::*;
use serde::{Deserialize, Serialize};
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
