# CLAUDE.md

Project context for Claude Code working on Gemma.Witness.

## What this is

Offline, multimodal, tamper-evident evidence-capture for civic accountability work. Tauri 2.x desktop app that records audio, accepts images, runs Gemma 4 E4B locally via mistralrs (or transformers fallback), and emits a signed `.witness` bundle that a separate static-HTML verifier can validate without a server.

Three components in one monorepo:
1. `apps/capture` (Tauri 2.x desktop)
2. `apps/verifier` (single HTML file plus WASM crypto)
3. `crates/witness-core` (Rust library: manifest, signing, bundle ZIP)

Plus optional `python/inference-sidecar/` if the transformers fallback is in use.

## Stack

| Layer | Tool | Version |
|---|---|---|
| Shell | Tauri | 2.x |
| Frontend | TypeScript + Svelte (no React) | TS 5.x, Svelte 5 |
| Backend | Rust | stable, MSRV 1.80 |
| Inference (dev + demo, Apple Silicon) | mlx-vlm | latest (0.4.3+) |
| Inference (cross-platform shipping) | mistralrs | latest |
| Inference (fallback) | transformers + Python | transformers 4.45+, Python 3.11+ |
| Audio capture | cpal | 0.15+ |
| Hashing | sha2 | 0.10+ |
| Signing | ed25519-dalek | 2.x |
| Key storage | keyring | 3.x |
| ZIP | zip | 2.x |
| Verifier crypto | @noble/ed25519 + @noble/hashes | latest stable |
| Verifier ZIP | fflate | latest stable |

## Engineering standards (non-negotiable)

These come from Brad's documented standards. Apply to every file, every commit, no exceptions.

**Filenames**: kebab-case. `bundle-builder.ts`, not `BundleBuilder.ts` or `bundle_builder.ts`. Rust files are snake_case per convention; that's the one exception (Rust modules are `snake_case` and that's idiomatic).

**Exports**: named exports only. No `export default`. If you need to re-export, use `export { X } from './x'`.

**TypeScript types**: no `any` anywhere. If a type is genuinely unknown, use `unknown` and narrow. If an upstream library has bad types, write a local declaration file; don't bypass with `any`.

**Rust**: no `unwrap()` or `expect()` in production code paths. Use `?` with typed errors via `thiserror`. `expect()` is only acceptable in tests, build scripts, or with a literal proof comment explaining why the failure is impossible.

**Docs**:
- TypeScript public functions get full JSDoc with `@param`, `@returns`, and `@throws` where applicable
- Rust public items get `///` doc comments
- Python public functions get type hints plus a one-line docstring; complex functions get full sphinx-style docstrings

**File size**: 300-line hard limit per file. Split before you hit it. If a file is approaching the limit, that's a signal it has too many responsibilities.

**DRY**: extract on the third repetition, not the second. Two similar blocks is a coincidence; three is a pattern.

**Errors**: every error message states what failed and what to do about it. Not "failed to read file." Yes "failed to read manifest at {path}: file does not exist. Ensure capture pass 4 completed before signing."

**Tests**: validate real behavior, not wiring. A test that mocks the thing being tested is broken. Integration tests beat unit tests when the integration is the actual contract (e.g., manifest signing and verification round-trip).

**No mocks of internal code**. External dependencies (HTTP, file system in some cases) can be mocked at the trait boundary. Internal logic gets tested with real inputs.

## Project structure

```
gemma-witness/
├── apps/
│   ├── capture/                  Tauri desktop app
│   │   ├── src/                  TypeScript + Svelte frontend
│   │   ├── src-tauri/            Rust backend
│   │   └── tauri.conf.json
│   └── verifier/                 Single-file static HTML verifier
│       ├── index.html
│       ├── verify.ts             (bundled to a single file via esbuild)
│       └── known-fingerprints.json   (generated from inference/fingerprints/)
├── crates/
│   ├── witness-core/             Manifest schema, hashing, signing, bundle I/O
│   ├── witness-cli/              CLI for testing without UI
│   ├── witness-inference/        HTTP client for the inference sidecar (OpenAI-compatible)
│   ├── witness-fingerprints/     Embedded registry baked from inference/fingerprints/
│   ├── witness-eval/             Evaluation harness
│   └── witness-test-sidecar/     Hermetic OpenAI-compatible fake (CI uses it for cross-platform e2e)
├── inference/
│   ├── fingerprints/             Unified (model_id, revision) -> sha256 registry, format=safetensors|gguf, primary_file names the anchored artifact
│   │   ├── index.json
│   │   └── <model>__<rev>.json   (one per pinned model revision)
│   ├── mlx-sidecar/              Apple Silicon dev/demo path (mlx-vlm)
│   │   └── start.sh              Wraps `mlx_vlm.server --model ... --port 8080`
│   ├── mistralrs-sidecar/        Cross-platform Rust inference path
│   │   ├── PINNED.json           Audited upstream commit + per-target SHA-256 of mistralrs-server
│   │   ├── start.sh              Gates launch on `check-pinned-binary`; refuses on hash mismatch
│   │   └── tests/start-sh-gate.sh   Integration test that the launch gate works
│   └── transformers-sidecar/     Cross-platform fallback (transformers + Python)
│       ├── start.py
│       └── requirements.txt
├── tools/
│   ├── seed-fingerprints/        Fetches HF LFS oid, cross-checks local cache, writes registry
│   └── check-pinned-binary/      Refuses sidecar launch when an inference binary's SHA-256 does not match PINNED.json
├── spec/
│   ├── manifest-schema.json      JSON Schema for the manifest
│   ├── incident-schema.json      JSON Schema for the structured incident report
│   └── bundle-format.md          Human-readable bundle spec
├── tests/
│   ├── fixtures/                 Sample audio, images, expected manifests
│   └── e2e/                      End-to-end capture + verify round-trips
└── docs/
```

## Critical invariants

These are bugs if violated, not stylistic preferences.

**The signature covers the canonicalized manifest.** Use RFC 8785 JCS for JSON canonicalization. If the manifest is re-serialized with different key ordering, the signature must still verify. Do not invent your own canonicalization.

**Asset hashes are over raw bytes**. SHA-256 of the WAV file as-written, JPEG as-written. No re-encoding, no normalization. The verifier recomputes the same bytes, gets the same hash.

**The reasoning trace is captured verbatim**. Whatever Gemma 4 emits in the thinking channel is what's stored, byte-for-byte. Do not strip whitespace, do not pretty-print, do not summarize.

**Private keys never leave the keychain**. Sign in Rust by passing the key handle to `ed25519-dalek`; do not export the key bytes to TypeScript. If you find yourself writing a "get private key" function that returns bytes, stop.

**Inference is non-deterministic**. Tests for the inference pipeline verify schema validity and field presence, not exact string output. Pin sampling parameters (temperature, top-k, top-p) so behavior is bounded, but don't assert on transcript wording.

**Model fingerprint pinning**. Fingerprints live in `inference/fingerprints/` and are embedded into the capture binary at compile time via the `witness-fingerprints` crate. At seal time the capture app queries the live sidecar's `/v1/models` and looks the active model up in that registry; if no entry exists, sealing fails with a clear error rather than recording an unverified hash. Updating an entry goes through `tools/seed-fingerprints`, which fetches the Hugging Face LFS oid for the pinned revision and refuses to write on mismatch. The verifier's `known-fingerprints.json` is generated from the same registry. Mismatch at verification time is a hard failure.

**Key provider abstraction**. All signing flows through the `KeyProvider` trait in `crates/witness-core/src/key_provider.rs`. Today only `SoftwareEd25519Provider` is wired up; future Secure-Enclave / TPM backends will plug in here without rewriting the seal path. The `hardware-keys` Cargo feature is reserved and fails the build until a real backend lands.

## Build, test, run

From the repo root:

```bash
# Install everything
pnpm install
cargo build --workspace

# Bring up the mlx-vlm inference sidecar (Apple Silicon dev path)
uv pip install mlx_vlm torchvision
mlx_vlm.server --model mlx-community/gemma-4-e4b-it-4bit --port 8080

# Dev: run the capture app with hot reload (in a separate terminal)
cd apps/capture && pnpm tauri dev

# Build the verifier (single HTML file output)
cd apps/verifier && pnpm build

# Run all Rust tests (run with --test-threads=1; keyring tests are not parallel-safe)
cargo test --workspace -- --test-threads=1

# Hermetic e2e against the in-process fake sidecar (cross-platform, no real model)
cargo test -p witness-core --test fake-sidecar-e2e -- --nocapture

# Live e2e against a running mlx-vlm sidecar on Apple Silicon
cargo test -p witness-core --test day-4-e2e -- --nocapture

# Lint
cargo clippy --workspace --all-targets -- -D warnings
pnpm lint

# Seed or refresh a model fingerprint from Hugging Face (run with the model cached locally)
cargo run -p seed-fingerprints -- --model-id mlx-community/gemma-4-e4b-it-4bit --revision cc3b666c01c20395e0dcebd53854504c7d9821f9

# CLI for testing without UI (requires sidecar running)
cargo run -p witness-cli -- capture --audio tests/fixtures/test.wav --image tests/fixtures/test.jpg
```

The capture app expects the inference sidecar at `http://localhost:8080`. The HTTP interface is OpenAI-compatible, so the cross-platform mistralrs path (when added for shipping) exposes the same endpoint shape and the Tauri Rust code doesn't change.

## Things to never do

- Re-implement crypto primitives. Use `sha2`, `ed25519-dalek`, `@noble/*`. Never write your own SHA-256 or signature code.
- Add a network dependency. The capture app must function fully offline. If a feature needs the internet, it doesn't belong here.
- Use `default` exports anywhere in TypeScript.
- Use `any` in TypeScript. Use `unknown` and narrow.
- Use `unwrap()` in Rust outside of tests.
- Mock internal logic in tests. Test it with real inputs.
- Ship a verifier that requires a server. The whole point is that anyone can verify with no infrastructure.
- Inline a private key in source, env file, or anywhere except the OS keychain.
- Modify the manifest schema without bumping the manifest version field. The verifier checks the version and routes to the correct validator.
- Use em dashes anywhere: source, docs, commit messages, error strings. Use commas, colons, semicolons, parentheses, or separate sentences.
- Write AI-pattern code: generic variable names (`data`, `result`, `obj` for non-obvious uses), over-commented obvious logic, boilerplate filler. Code should look like a senior engineer wrote it deliberately.

## When you're not sure

Default to the safer, simpler option. This is a verification system; trust depends on minimizing what can go wrong. A boring well-tested choice beats a clever one every time.

If a design decision affects the bundle format, the signing flow, or the verifier behavior, ask before changing it. These three things are the spec of the system; changing them silently breaks verifiers in the wild.

## Test strategy

Four layers:

**Unit (Rust)**: pure functions in `witness-core` and `witness-fingerprints` get unit tests. Canonicalization, hashing, manifest serialization, signature verification, registry lookup. Fast, deterministic, run on every save.

**Integration (Rust)**: spawn the inference sidecar (real or fake), feed fixture inputs, assert the output matches the incident schema. Slower, run on push to a feature branch.

**Hermetic end-to-end**: `crates/witness-test-sidecar` serves OpenAI-compatible fixture responses; the test in `crates/witness-core/tests/fake-sidecar-e2e.rs` drives the full pipeline through to a sealed and verified bundle, plus a byte-level tamper assertion. Runs on every push on Linux, Windows, and macOS. No real model required.

**Live end-to-end**: `crates/witness-core/tests/day-4-e2e.rs` does the same path against a real mlx-vlm sidecar. Runs locally on Apple Silicon; in CI it compiles and exits via its skip path because the runner can't host the model.

Coverage target: 80%+ on `witness-core` (the cryptographic and serialization paths). Lower coverage acceptable on the Tauri shell since UI testing has diminishing returns at this stage.

## Commit and PR conventions

Conventional commits (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`). One concern per commit. PRs should be reviewable in 10 minutes; if it's bigger, split it.

Every PR that touches `witness-core` or the manifest schema requires the e2e test to pass. CI enforces this.
