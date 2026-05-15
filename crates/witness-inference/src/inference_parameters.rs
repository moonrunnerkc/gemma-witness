//! Build the optional `gemma.witness.inference_parameters` assertion from
//! the constants each pass currently runs with.
//!
//! Forensic, not cryptographic. The values let an offline analyst run the
//! same model with the same parameters and decide whether the sealed
//! reasoning trace is a plausible draw. The verifier displays the data; it
//! does not pass or fail on it.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use witness_core::{InferenceParameters, PassParameters};

use crate::client::{
    DEFAULT_MAX_TOKENS as STRUCTURE_MAX_TOKENS, DEFAULT_TEMPERATURE, DEFAULT_TOP_P,
};
use crate::passes::analyze_image::{
    DEFAULT_VISUAL_TOKEN_BUDGET, MAX_TOKENS as ANALYZE_MAX_TOKENS, PROMPT as ANALYZE_PROMPT,
    TEMPERATURE as ANALYZE_TEMPERATURE,
};
use crate::passes::check_consistency::{
    MAX_TOKENS as CONSISTENCY_MAX_TOKENS, SYSTEM_PROMPT as CONSISTENCY_PROMPT,
    TEMPERATURE as CONSISTENCY_TEMPERATURE,
};
use crate::passes::transcribe::{
    MAX_TOKENS as TRANSCRIBE_MAX_TOKENS, PROMPT as TRANSCRIBE_PROMPT,
    TEMPERATURE as TRANSCRIBE_TEMPERATURE,
};

const NOTE: &str = "advisory. sampling parameters captured at seal time so an offline analyst can \
re-derive a similar-distribution trace from the same model. not a security primitive, not part of \
the verifier's pass/fail logic.";

/// Build the parameter snapshot for the four passes shipped today.
///
/// The function takes the structure-incident system prompt by reference
/// because the production prompt is loaded as a workspace constant in
/// [`crate::client::SYSTEM_PROMPT`]; tests can pass a different prompt to
/// confirm the SHA changes accordingly.
pub fn snapshot() -> InferenceParameters {
    snapshot_with_structure_prompt(crate::client::SYSTEM_PROMPT)
}

/// Variant of [`snapshot`] that lets a caller substitute the structure-incident
/// prompt. Intended for tests; production code calls [`snapshot`].
pub fn snapshot_with_structure_prompt(structure_prompt: &str) -> InferenceParameters {
    let mut passes: BTreeMap<String, PassParameters> = BTreeMap::new();

    passes.insert(
        "transcribe".to_string(),
        PassParameters {
            temperature: TRANSCRIBE_TEMPERATURE,
            top_p: None,
            max_tokens: TRANSCRIBE_MAX_TOKENS,
            visual_token_budget: None,
            prompt_sha256: sha256_hex(TRANSCRIBE_PROMPT.as_bytes()),
        },
    );

    passes.insert(
        "structure_incident".to_string(),
        PassParameters {
            temperature: DEFAULT_TEMPERATURE,
            top_p: Some(DEFAULT_TOP_P),
            max_tokens: STRUCTURE_MAX_TOKENS,
            visual_token_budget: None,
            prompt_sha256: sha256_hex(structure_prompt.as_bytes()),
        },
    );

    passes.insert(
        "analyze_image".to_string(),
        PassParameters {
            temperature: ANALYZE_TEMPERATURE,
            top_p: None,
            max_tokens: ANALYZE_MAX_TOKENS,
            visual_token_budget: Some(DEFAULT_VISUAL_TOKEN_BUDGET),
            prompt_sha256: sha256_hex(ANALYZE_PROMPT.as_bytes()),
        },
    );

    passes.insert(
        "check_consistency".to_string(),
        PassParameters {
            temperature: CONSISTENCY_TEMPERATURE,
            top_p: None,
            max_tokens: CONSISTENCY_MAX_TOKENS,
            visual_token_budget: None,
            prompt_sha256: sha256_hex(CONSISTENCY_PROMPT.as_bytes()),
        },
    );

    InferenceParameters {
        passes,
        sampling_seed: None,
        note: NOTE.to_string(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_includes_all_four_passes() {
        let params = snapshot();
        for pass in [
            "transcribe",
            "structure_incident",
            "analyze_image",
            "check_consistency",
        ] {
            assert!(
                params.passes.contains_key(pass),
                "missing pass entry: {pass}"
            );
        }
    }

    #[test]
    fn analyze_image_carries_visual_token_budget() {
        let params = snapshot();
        let analyze = params.passes.get("analyze_image").expect("analyze pass");
        assert!(
            analyze.visual_token_budget.is_some(),
            "analyze_image must record its visual token budget"
        );
        assert_eq!(
            analyze.visual_token_budget.unwrap(),
            DEFAULT_VISUAL_TOKEN_BUDGET
        );
    }

    #[test]
    fn prompt_sha_changes_when_prompt_changes() {
        let base = snapshot();
        let modified = snapshot_with_structure_prompt("a different system prompt");
        let base_sha = &base.passes.get("structure_incident").unwrap().prompt_sha256;
        let modified_sha = &modified
            .passes
            .get("structure_incident")
            .unwrap()
            .prompt_sha256;
        assert_ne!(base_sha, modified_sha);
    }
}
