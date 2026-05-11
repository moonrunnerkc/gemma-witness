# GitHub Copilot Instructions

Place this file at `.github/copilot-instructions.md` in the repo root. Copilot reads it automatically and applies these rules to inline completions and chat answers.

## Project: Gemma.Witness

Offline multimodal evidence-capture system. Tauri 2.x desktop app + static HTML verifier. Records audio, accepts images, runs Gemma 4 E4B locally, emits a signed `.witness` bundle that the verifier validates without a server. Three components: `apps/capture` (Tauri), `apps/verifier` (static HTML), `crates/witness-core` (Rust manifest/signing/bundle library).

## Code style (apply to every suggestion)

**TypeScript**:
- No `any`. Use `unknown` and narrow with type guards, or define a precise type.
- Named exports only. No `export default`.
- Filenames: kebab-case (`bundle-builder.ts`).
- Full JSDoc on every exported function: `@param`, `@returns`, `@throws`.
- Use `const` over `let` wherever the binding doesn't reassign.
- Arrow functions for utilities, `function` declarations for top-level handlers.
- No unnecessary semicolons; follow the existing file's style.

**Rust**:
- No `unwrap()` or `expect()` in non-test code. Return `Result<T, E>` with typed errors via `thiserror`.
- File and module names: snake_case (Rust convention).
- Use `?` for error propagation. No `match` on `Result` just to call `unwrap_or_default`.
- Doc comments (`///`) on all public items.
- Prefer `&str` over `String` in function signatures unless ownership is required.
- Derive `Debug`, `Clone`, `Serialize`, `Deserialize` on data types; never derive `Copy` on anything containing crypto material.

**Python** (inference sidecar only):
- Type hints on every function signature.
- One-line docstring minimum on public functions; full docstring for anything non-obvious.
- Use `pathlib.Path` over string paths.
- No bare `except`. Catch specific exceptions.

**Universal**:
- No em dashes anywhere: code, comments, docs, commit messages, error strings. Use commas, colons, semicolons, parentheses, or separate sentences.
- 300-line file limit. If a file approaches the limit, refactor into smaller modules.
- DRY at three repetitions, not two.
- Error messages state what failed and what to do about it.

## Things to never suggest

- `export default` anything
- `any` in TypeScript
- `unwrap()` or `panic!()` outside of tests
- Inline crypto implementations (SHA-256, Ed25519, etc.); always pull from `sha2`, `ed25519-dalek`, `@noble/*`
- Network calls in the capture app
- Server-side endpoints in the verifier
- Mocks of internal modules in tests
- Generic variable names like `data`, `result`, `obj`, `tmp`, `foo`, `bar` outside of trivial closures
- Comments that restate what the code already says (`// increment i by 1`)
- `// TODO` without an issue number or assigned owner
- Em dashes
- Hashtags or emoji in code, comments, or docs

## Things to prefer

- `Result<T, WitnessError>` over panicking
- `&str` over `String` in function signatures
- Iterator chains over imperative loops when both read clearly
- `tracing` for logging in Rust, `console.log` only in dev-only frontend code
- `serde_json::Value` only at trust boundaries; use typed structs everywhere else
- Constants for magic numbers, with a comment explaining the choice
- Property tests (`proptest` in Rust) for serialization round-trips
- Integration tests over unit tests when the integration is the contract being verified

## Project invariants Copilot should respect

These are correctness requirements. Violating them breaks the system, not just the style.

**The signature covers the canonicalized manifest using RFC 8785 JCS.** Any suggestion that signs raw JSON without canonicalization is wrong. Use the `serde_jcs` crate.

**Asset hashes are computed over raw file bytes.** Suggestions that hash decoded content (e.g., decoded PCM samples instead of the WAV bytes) are wrong. Read the file with `std::fs::read`, hash with `sha2::Sha256`.

**Private keys live in the OS keychain.** Suggestions that store private keys in files, env vars, or memory beyond the signing call are wrong. Use the `keyring` crate to fetch a handle, sign, drop the handle.

**The reasoning trace is captured verbatim.** Suggestions that pretty-print, summarize, or trim the Gemma 4 thinking-channel output are wrong. Store the raw string, hash it, sign over the hash.

**Inference is non-deterministic.** Suggestions for tests that assert on exact transcript output are wrong. Assert on schema validity, field presence, type correctness; never on exact strings.

**The verifier is a single HTML file with WASM crypto, no server.** Suggestions that introduce a backend endpoint, fetch from a remote URL at verify time, or require Node.js to run are wrong.

**Bundle format is a versioned spec.** Suggestions that change the manifest structure without bumping `manifest_version` and updating the verifier's version routing are wrong.

## Common task patterns

**Adding a new manifest assertion type**:
1. Define the assertion shape in `spec/manifest-schema.json`
2. Add the typed struct to `crates/witness-core/src/assertions/`
3. Update the canonical-ordering test in `crates/witness-core/tests/canonicalization.rs`
4. Update the verifier's per-assertion handler in `apps/verifier/src/assertions/`
5. Add an e2e test that emits and verifies a bundle containing the new assertion

**Adding a Tauri command**:
1. Define the command in `apps/capture/src-tauri/src/commands/`
2. Return `Result<T, AppError>` where `AppError: serde::Serialize`
3. Register in `lib.rs` invoke handler
4. Generate TypeScript bindings (`pnpm bindings:generate`)
5. Call from frontend with the generated types; do not hand-write the invocation

**Adding a test fixture**:
1. Put the raw asset in `tests/fixtures/`
2. Generate the expected manifest with the CLI: `cargo run -p witness-cli -- capture --fixture-mode`
3. Commit both the input and the expected manifest
4. Use in tests with `include_bytes!` for raw assets and `include_str!` for manifests

## Comment style

Comments explain why, not what.

Good:
```rust
// RFC 8785 requires sorted keys; serde_json's default serialization doesn't sort.
let canonical = serde_jcs::to_vec(&manifest)?;
```

Bad:
```rust
// Serialize the manifest to a canonical byte string
let canonical = serde_jcs::to_vec(&manifest)?;
```

Never use comments that read like AI output: "This function takes X and returns Y by doing Z." If the function signature already says that, the comment is noise.

## Test naming

Test names describe behavior, not implementation. The name should read as a sentence about what the system does.

Good:
- `verifies_bundle_with_matching_signature_succeeds`
- `rejects_bundle_after_audio_byte_modification`
- `fails_signature_when_manifest_keys_reordered_without_canonicalization`

Bad:
- `test_verify`
- `test_signature_1`
- `test_bundle_handler`

## Error type pattern (Rust)

Define one error type per crate, namespaced. Use `thiserror`.

```rust
#[derive(Debug, thiserror::Error)]
pub enum WitnessCoreError {
    #[error("manifest at {path} could not be read: {source}")]
    ManifestRead { path: String, #[source] source: std::io::Error },

    #[error("manifest signature verification failed: signature does not match canonicalized payload")]
    SignatureInvalid,
}
```

Error variants include enough context to act on the error: paths, IDs, sizes. Never just "operation failed."

## When Copilot is unsure

Default to the verbose-but-correct option. If a suggestion would be wrong but plausible, generate nothing and let the developer write it. This is a security-sensitive system; "almost right" is worse than empty.

If the developer is writing crypto, signing, or bundle-format code, prefer suggestions that reference the appropriate crate's documented API rather than inlining logic. If you don't know the exact API, suggest the crate import and let the developer fill in.

## What this project is not

To prevent Copilot from suggesting patterns from adjacent domains:

- Not a clinical scribe. Don't suggest medical terminology or SOAP-note structure.
- Not a hosted API service. Don't suggest auth middleware, rate limiting, or REST endpoints.
- Not a blockchain. Don't suggest smart contract, anchoring, or consensus code.
- Not a zero-knowledge proof system. Don't suggest circuit code or zk libraries.
- Not a media-only provenance tool. Don't restrict assertions to image/video metadata.

The novel piece is the combination of multimodal AI reasoning, hash-chained provenance, offline operation, and standards-aligned but extended manifests. Suggestions should support that combination, not optimize for any one piece in isolation.
