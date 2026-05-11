# Gemma.Witness

Offline, multimodal, tamper-evident evidence capture for civic accountability work.

Gemma.Witness records audio, accepts images, runs Gemma 4 E4B locally through an mlx-vlm sidecar on Apple Silicon (mistralrs for cross-platform shipping), and emits a signed `.witness` bundle that a standalone static-HTML verifier can validate without a server.

Three components live in this repo:

- `apps/capture`: Tauri 2 desktop app (Svelte 5 + TypeScript 5 frontend, Rust backend)
- `apps/verifier`: single-file static HTML verifier (complete and working)
- `crates/witness-core`: Rust library: manifest, canonicalization, hashing, Ed25519 signing, ZIP bundle I/O, OS-keychain device keys, round-trip verifier

Plus:

- `crates/witness-inference`: typed async HTTP client for the local OpenAI-compatible sidecar; runs the four-pass pipeline (transcribe, structure, per-image analysis, consistency check with thinking-mode reasoning)
- `crates/witness-cli`: headless CLI that drives the full pipeline against fixtures
- `inference/mlx-sidecar`: `mlx_vlm.server` launcher and a pinned model fingerprint
- `spec/`: manifest schema, incident-report schema, bundle-format document

## Status

Working end-to-end on macOS Apple Silicon. A live test passes against the local sidecar:

- inference pipeline: transcribe → structured incident report → per-image descriptions → consistency verdict with verbatim reasoning trace
- bundle seal: typed manifest, RFC 8785 JCS canonicalization, Ed25519 signature from an OS-keychain device key, deterministic ZIP layout
- round-trip verify: signature, per-asset SHA-256 hashes, and model-fingerprint allowlist all checked independently
- tamper detection: flipping a byte inside the sealed audio is detected at the asset-hash step, not at the signature

What's done:

- [x] Local inference sidecar bring-up with a pinned Gemma 4 E4B fingerprint
- [x] Four-pass multimodal pipeline with thinking-mode reasoning captured verbatim
- [x] `witness-core` types, JCS canonicalization, SHA-256 asset hashing, Ed25519 signing, deterministic `.witness` ZIP, round-trip verifier, OS-keychain device-key handling
- [x] Capture-app Tauri commands: device init, audio record/stop (cpal, 16 kHz mono, 30 s cap), image picker (jpg/jpeg/png, 10 MB, 4 max), full-pipeline inference, seal bundle
- [x] Minimum-viable Svelte 5 UI wired to those commands
- [x] Static HTML verifier with zero external network calls: drag-and-drop bundle validation, signature verification via `@noble/ed25519`, asset hash recomputation via `@noble/hashes`, ZIP extraction via `fflate`, JCS canonicalization via `canonicalize`

What's next:

- [ ] Cross-platform inference path via mistralrs so the capture app ships beyond Apple Silicon
- [ ] Frontend polish, generated Tauri bindings (`tauri-specta`) replacing the hand-written typing layer, packaging
- [ ] CI coverage reporting (`cargo-tarpaulin`)

## Repository layout

```
gemma-witness/
├── apps/
│   ├── capture/                  Tauri desktop app
│   │   ├── src/                  Svelte 5 + TypeScript frontend
│   │   └── src-tauri/            Rust backend, cpal audio, plugin-dialog images
│   └── verifier/                 Static HTML verifier (complete)
├── crates/
│   ├── witness-core/             Manifest, hashing, signing, keystore, bundle I/O, verifier
│   ├── witness-cli/              Headless pipeline runner
│   ├── witness-inference/        Local sidecar HTTP client and four-pass pipeline
│   └── witness-eval/             Scenario evaluation harness
├── inference/
│   ├── mlx-sidecar/              Apple Silicon dev path (mlx-vlm), pinned model fingerprint
│   └── transformers-sidecar/     Cross-platform fallback scaffolding
├── spec/
│   ├── manifest-schema.json      Manifest JSON Schema
│   ├── incident-schema.json      Structured incident report JSON Schema
│   └── bundle-format.md          `.witness` ZIP layout and ordering rules
├── tests/
│   └── fixtures/                 Audio and image fixtures used by integration tests
└── docs/
```

## Build and test

Prerequisites: macOS Apple Silicon, Rust stable (MSRV 1.80), `pnpm`, `uv` for the Python sidecar.

```bash
# install everything
pnpm install
cargo build --workspace

# bring up the mlx-vlm inference sidecar
./inference/mlx-sidecar/start.sh

# run the capture app with hot reload (separate terminal)
cd apps/capture && pnpm tauri dev

# all Rust tests (run serialized while the sidecar is single-request multimodal)
cargo test --workspace -- --test-threads=1

# the headless end-to-end (seal + verify + tamper) against the live sidecar
cargo test -p witness-core --test day-4-e2e -- --nocapture

# build the static verifier HTML file
cd apps/verifier && pnpm build

# run the verifier JS end-to-end tests against the fixture bundle
cd apps/verifier && npx tsx tests/e2e.test.ts

# lint
cargo clippy --workspace --all-targets -- -D warnings
pnpm lint

# headless pipeline run
cargo run -p witness-cli -- pipeline \
  --audio tests/fixtures/day-3-scenarios/1/audio.wav \
  --images tests/fixtures/day-3-scenarios/1/image1.jpg \
           tests/fixtures/day-3-scenarios/1/image2.jpg
```

The capture app expects the sidecar at `http://localhost:8080`. The HTTP surface is OpenAI-compatible so the future cross-platform mistralrs path keeps the same endpoint shape and Tauri does not change.

## Invariants

These are correctness requirements, not style preferences. They show up in every PR review:

- The signature covers the RFC 8785 JCS canonicalized manifest bytes, never raw `serde_json` output.
- Asset hashes are SHA-256 of the raw file bytes. No re-encoding, no normalization.
- Private keys live in the OS keychain. Nothing exports the seed bytes; signing happens inside `witness-core::keystore`.
- The reasoning trace is stored verbatim. No trimming, pretty-printing, or summarization before hashing.
- The capture app never reaches the network beyond `localhost:8080`.
- The verifier is a single HTML file with WASM crypto and no server.
- `manifest_version` is mandatory and bumps in lockstep with verifier routing changes.

## Standards

See `CLAUDE.md` for full engineering standards and `.github/copilot-instructions.md` for style and forbidden-patterns rules applied to every commit. The non-negotiables:

- No `unwrap()` or `expect()` in non-test Rust paths; typed errors via `thiserror`.
- No `any` in TypeScript; `unknown` plus narrowing.
- Named exports only. Kebab-case TS filenames, snake_case Rust modules.
- 300-line per-file ceiling.
- Crypto comes from `sha2`, `ed25519-dalek`, `serde_jcs` on the Rust side and `@noble/*` on the JS side. Never inlined.

## License

MIT.
