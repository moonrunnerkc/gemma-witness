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
│       └── known-fingerprints.json
├── crates/
│   ├── witness-core/             Manifest schema, hashing, signing, bundle I/O
│   ├── witness-cli/              CLI for testing without UI
│   └── witness-inference/        HTTP client for the inference sidecar (OpenAI-compatible)
├── inference/
│   ├── mlx-sidecar/              Apple Silicon dev/demo path (mlx-vlm)
│   │   └── start.sh              Wraps `mlx_vlm.server --model ... --port 8080`
│   └── transformers-sidecar/     Cross-platform fallback (transformers + Python)
│       ├── sidecar.py
│       └── requirements.txt
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

**Model fingerprint pinning**. The verifier ships a list of known good Gemma 4 model fingerprints (SHA-256 of the `.safetensors` files). The capture app computes the fingerprint of the loaded model and includes it in the manifest. Mismatch is a hard failure in the verifier.

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

# Run all Rust tests
cargo test --workspace

# Run the end-to-end test (captures a fixture, signs, verifies)
cargo test --test e2e -- --nocapture

# Lint
cargo clippy --workspace -- -D warnings
pnpm lint

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

Three layers:

**Unit (Rust)**: pure functions in `witness-core` get unit tests. Canonicalization, hashing, manifest serialization, signature verification. Fast, deterministic, run on every save.

**Integration (Rust + Python)**: spawn the inference sidecar, feed a fixture audio file, assert the output matches the incident schema. Slower, run on push to a feature branch.

**End-to-end**: full pipeline from audio capture (or pre-recorded fixture) through to a verified bundle. The same test creates the bundle and runs the verifier logic on it. Catches schema drift between capture and verify. Runs on every PR.

Coverage target: 80%+ on `witness-core` (the cryptographic and serialization paths). Lower coverage acceptable on the Tauri shell since UI testing has diminishing returns at this stage.

## Commit and PR conventions

Conventional commits (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`). One concern per commit. PRs should be reviewable in 10 minutes; if it's bigger, split it.

Every PR that touches `witness-core` or the manifest schema requires the e2e test to pass. CI enforces this.
