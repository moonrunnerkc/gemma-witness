# Day 2 decisions

One-line entries. Goal: auditability of non-trivial choices made during Day 2.

- Workspace: created the Rust workspace at the repo root with members `witness-core`, `witness-inference`, `witness-cli`, `witness-eval`. Day 1 had no Cargo workspace; Day 2 introduces it because every Day 2 deliverable is Rust.
- Function-calling path: chose the OpenAI `tools` parameter (with `tool_choice` forcing `record_incident`). Verified support against the running mlx-vlm 0.5.0 sidecar before committing; the response includes a `tool_calls[0].function.arguments` JSON string that the client parses and validates. JSON-mode prompting was prepared as a fallback but not needed.
- Schema validator: `jsonschema` 0.18 (`JSONSchema::compile`). 0.18 is the latest version on crates.io that matches the spec's draft 2020-12 features without requiring an unreleased build. If we move to draft 2020-12 strict mode later, revisit.
- Sampling: `temperature=0.2`, `top_p=0.9`, both pinned in code as constants with rationale comments. No implicit defaults.
- Retry policy: up to 3 retries on schema-validation failure, with the last failing arguments and validator error fed back into the next prompt. Beyond 3 returns `InferenceError::SchemaInvalid`.
- Transcripts: synthesized (not scraped) from public-domain incident-reporting patterns. The OSHA accident-search results are a JS-rendered SPA that does not return narrative text in static HTML; rather than ship an unreliable scraper, the README documents the synthesis and links each transcript to its pattern source. Permitted explicitly by the build guide.
- Incident type for vehicle defect (transcript 08): mapped to `other`. The schema enum has no `vehicle_defect`. Documented in fixtures README.
- Eval harness: implemented as a Rust binary `witness-eval`, not a Python script, to keep the entire Day 2 deliverable inside the Cargo workspace and reuse the typed inference client without re-deriving the prompt and retry logic.
- Schema location passed to the model: the JSON Schema is embedded verbatim as the `function.parameters` of the tool, including `additionalProperties: false`. The model's tool-call arguments are then re-validated against the same schema in Rust before any acceptance.
