<p align="center">
  <img src="docs/cover.svg" alt="Gemma.Witness: offline, multimodal, tamper-evident evidence capture" width="100%">
</p>

<h1 align="center">Gemma.Witness</h1>

<p align="center">
  Offline, multimodal evidence capture that emits a signed, locally verifiable bundle.
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-7dd3fc?style=flat-square"></a>
  <img alt="Rust 1.80+" src="https://img.shields.io/badge/rust-1.80%2B-1a2548?style=flat-square&logo=rust&logoColor=ffffff">
  <img alt="Node 22" src="https://img.shields.io/badge/node-22.x-1a2548?style=flat-square&logo=node.js&logoColor=ffffff">
  <img alt="Tauri 2" src="https://img.shields.io/badge/tauri-2.x-1a2548?style=flat-square&logo=tauri&logoColor=ffffff">
  <img alt="Status: pre-release" src="https://img.shields.io/badge/status-pre--release-a78bfa?style=flat-square">
</p>

---

## What this is

Gemma.Witness records audio and accompanying images on a workstation, runs a local Gemma vision-language model through a four-pass pipeline to produce a structured incident report plus a verbatim reasoning trace, then seals the inputs and the model outputs into a `.witness` ZIP. The bundle is Ed25519-signed by a device key held in the OS keychain. A separate single-file static-HTML verifier reads the bundle, recomputes hashes, validates the signature, and checks the model fingerprint against a pinned allow-list, with zero network access.

The whole capture and verify chain is designed to run without an internet connection.

This is a pre-release research project. Read the [Repository Health Findings](#repository-health-findings) and [Reality Check](#reality-check) sections before relying on it.

## Architecture

```
┌──────────────────────┐    ┌──────────────────────────┐    ┌──────────────────────┐
│  Capture (Tauri 2)   │    │  Inference sidecar       │    │  .witness ZIP        │
│  apps/capture        │───▶│  inference/{mlx,         │───▶│  manifest.json       │
│  Svelte 5 + Rust     │    │   mistralrs,             │    │  signature.json      │
│  cpal audio, dialog  │    │   transformers}          │    │  public_key.pem      │
└──────────┬───────────┘    │  OpenAI-compatible HTTP  │    │  assets/audio.wav    │
           │                └──────────────────────────┘    │  assets/images/...   │
           │                                                │  assets/reasoning.txt│
           │                                                └──────────┬───────────┘
           │ Ed25519 sign over RFC 8785 JCS                            │
           │ key lives in OS keychain                                  ▼
           │                                                ┌──────────────────────┐
           └───────────────────────────────────────────────▶│  Verifier (HTML)     │
                                                            │  apps/verifier       │
                                                            │  noble crypto + fflate│
                                                            │  one self-contained  │
                                                            │  file, no network    │
                                                            └──────────────────────┘
```

### Execution flow

1. User records audio (cpal, mono 16 kHz WAV, 30 s cap) and picks images.
   Evidence: `apps/capture/src-tauri/src/audio.rs:18-21`, `apps/capture/src-tauri/src/commands/{audio_commands,image_commands}.rs`.
2. The capture app calls the local sidecar via an OpenAI-compatible HTTP API to run four passes: transcribe, structure, per-image analysis, consistency.
   Evidence: `crates/witness-inference/src/pipeline.rs`, `crates/witness-inference/src/passes/*.rs`.
3. The structured report and consistency verdict are surfaced to the user for review.
   Evidence: `apps/capture/src/app.svelte`.
4. The user seals the bundle. The bundle builder hashes every raw asset, serializes the manifest with `serde_jcs` (RFC 8785), signs the canonical bytes with the Ed25519 key from the OS keychain, and writes a deterministic ZIP.
   Evidence: `crates/witness-core/src/bundle_builder.rs`, `crates/witness-core/src/keystore.rs`, `crates/witness-core/src/canonical.rs`.
5. The verifier reads the ZIP, re-canonicalizes the manifest, checks the signature, recomputes asset hashes, and matches the model fingerprint against `known-fingerprints.json`.
   Evidence: `apps/verifier/src/verify-logic.ts`, `apps/verifier/src/verify-signature.ts`, `apps/verifier/src/verify-asset-hashes.ts`, `apps/verifier/src/verify-model-fingerprint.ts`.

### Crates and apps

| Path | Purpose |
| :--- | :--- |
| `crates/witness-core` | Manifest types, JCS canonicalization, SHA-256 hashing, Ed25519 sign and verify, keystore, deterministic ZIP writer, round-trip verifier. |
| `crates/witness-inference` | HTTP client for the sidecar plus the four-pass pipeline (`transcribe`, `analyze_image`, `check_consistency`, plus `structure_incident`). |
| `crates/witness-cli` | `witness` CLI driver with `structure` and `pipeline` subcommands. |
| `crates/witness-eval` | Markdown-emitting evaluation harness for the Day 2 structured-extraction work (`tests/fixtures/transcripts/`). |
| `apps/capture/src-tauri` | Tauri 2 backend: audio capture, image dialog, inference command, seal command, device key bootstrap. |
| `apps/capture/src` | Svelte 5 frontend wired to `tauri-specta`-generated TypeScript bindings. |
| `apps/verifier` | Static HTML verifier bundled to a single `dist/verify.html` by `build.mjs`. |
| `inference/mlx-sidecar` | Apple Silicon path using `mlx-vlm`'s OpenAI-compatible server. |
| `inference/mistralrs-sidecar` | Cross-platform path using `mistralrs serve`. |
| `inference/transformers-sidecar` | FastAPI shim around Hugging Face Transformers for fallback hardware. |

## Verified features

| Feature | Status | Evidence |
| :--- | :--- | :--- |
| Audio capture (cpal, 16 kHz mono WAV, 30 s cap) | Implemented | `apps/capture/src-tauri/src/audio.rs` |
| Image picking via Tauri dialog | Implemented | `apps/capture/src-tauri/src/commands/image_commands.rs` |
| Four-pass multimodal pipeline | Implemented | `crates/witness-inference/src/pipeline.rs`, `crates/witness-inference/src/passes/` |
| OpenAI-compatible sidecar client | Implemented | `crates/witness-inference/src/{client,http,response}.rs` |
| Structured incident report (JSON Schema constrained) | Implemented | `spec/incident-schema.json`, `crates/witness-inference/src/client.rs` |
| Verbatim reasoning trace capture | Implemented | `crates/witness-inference/src/passes/check_consistency.rs`, `apps/capture/src-tauri/src/commands/inference_commands.rs:62-66` |
| Manifest schema v1 (typed) | Implemented | `spec/manifest-schema.json`, `crates/witness-core/src/manifest.rs` |
| RFC 8785 JCS canonicalization for the signing payload | Implemented | `crates/witness-core/src/canonical.rs` (via `serde_jcs`) |
| Ed25519 signing | Implemented | `crates/witness-core/src/signing.rs` |
| OS keychain key storage (`keyring` crate) | Implemented | `crates/witness-core/src/keystore.rs` |
| Deterministic ZIP writer (sorted entries, STORED, epoch mtime) | Implemented | `crates/witness-core/src/bundle_zip.rs`, `spec/bundle-format.md:46-49` |
| Round-trip Rust verifier | Implemented | `crates/witness-core/src/verifier.rs`, `crates/witness-core/tests/bundle_roundtrip.rs` |
| Static HTML verifier (single file, no network) | Implemented | `apps/verifier/verify.ts`, `apps/verifier/build.mjs:55-75` |
| Verifier signature + hash + fingerprint + manifest_version checks | Implemented | `apps/verifier/src/verify-logic.ts`, `apps/verifier/tests/e2e.test.ts` (7 cases, all pass) |
| Model fingerprint pinning | Implemented (with caveat) | `apps/verifier/known-fingerprints.json`, `inference/*/model-fingerprint.json` |
| `tauri-specta` TypeScript bindings | Implemented | `apps/capture/src-tauri/src/lib.rs:37-42`, `apps/capture/src/bindings.ts` (generated) |
| CLI (`witness`) for headless pipeline runs | Implemented | `crates/witness-cli/src/main.rs` |
| Evaluation harness with confusion matrix and latency percentiles | Implemented | `crates/witness-eval/src/main.rs` |
| GitHub Actions CI (fmt, clippy, build, test, coverage, verifier, em-dash scan) | Implemented | `.github/workflows/ci.yml` |
| Rust coverage via `cargo-tarpaulin` | Implemented in CI | `.github/workflows/ci.yml:34-66` |
| Apple Silicon sidecar (mlx-vlm) | Implemented | `inference/mlx-sidecar/start.sh`, `inference/mlx-sidecar/pyproject.toml` |
| mistralrs sidecar | Implemented (script wrappers + fingerprint placeholder) | `inference/mistralrs-sidecar/start.sh`, `inference/mistralrs-sidecar/README.md` |
| transformers sidecar (FastAPI) | Implemented | `inference/transformers-sidecar/start.py` (FastAPI + `AutoModelForImageTextToText`) |
| Live end-to-end Rust test against a running sidecar | Partial | `crates/witness-core/tests/day-4-e2e.rs:7-9` skips with a message when sidecar is unreachable. |
| Cross-platform live capture (Linux, Windows) | Unverified | No fixtures or CI lane exercises mistralrs or transformers end-to-end. |
| Hardware attestation, TPM or TEE binding | Not implemented | None. Key is software-held in the OS keychain. |

## Installation

### Prerequisites

| Tool | Version (from repo) | Source |
| :--- | :--- | :--- |
| Rust toolchain | stable, MSRV `1.80` | `Cargo.toml:14`, `rust-toolchain` not pinned |
| Node | `22.x` (CI), `pnpm` `9` (CI) | `.github/workflows/ci.yml:74-82` |
| Python | `>=3.13,<3.14` for `mlx-sidecar` | `inference/mlx-sidecar/pyproject.toml:5` |
| `uv` | recommended | used in `mlx-sidecar/start.sh:33` |
| OS for `mlx-sidecar` | macOS on Apple Silicon | `mlx-vlm` requirement |
| OS for `mistralrs-sidecar` | Linux, macOS, or Windows | `inference/mistralrs-sidecar/README.md:62-65` |

### Setup

```bash
# Clone, then from the repo root:
cargo build --workspace

# Verifier
cd apps/verifier && pnpm install --frozen-lockfile && pnpm build && cd -

# Capture app: install JS deps (note: apps/capture has no committed lockfile)
cd apps/capture && pnpm install
```

> Note: `apps/capture/` has a `package.json` but no `pnpm-lock.yaml`. The verifier directory does. CI only installs verifier deps.

### Inference sidecar (one of three)

```bash
# Apple Silicon (primary path used by Day 4 fixtures)
./inference/mlx-sidecar/start.sh

# Cross-platform (Rust)
./inference/mistralrs-sidecar/start.sh
./inference/mistralrs-sidecar/compute-fingerprint.sh   # required: see Health Findings

# Pure Python fallback
cd inference/transformers-sidecar && pip install -r requirements.txt && python start.py
```

All three sidecars bind to `127.0.0.1:8080` by default and speak the OpenAI `chat/completions` API. The capture app talks to that endpoint; switching sidecars requires no Rust changes.

## Usage

### CLI pipeline

```bash
# Send a transcript through pass 1 (structure) only
cargo run -p witness-cli -- structure \
  --transcript tests/fixtures/day1-sample.txt

# Run the full four-pass pipeline against fixtures
cargo run -p witness-cli -- pipeline \
  --audio tests/fixtures/day-3-scenarios/1/audio.wav \
  --image tests/fixtures/day-3-scenarios/1/image1.jpg \
  --image tests/fixtures/day-3-scenarios/1/image2.jpg
```

The CLI writes pretty-printed JSON to stdout and a one-line success summary to stderr.
Evidence: `crates/witness-cli/src/main.rs:101-110`.

### Capture app

```bash
cd apps/capture && pnpm tauri dev
```

The UI is intentionally minimal: record audio, pick images, run inference, review, seal.
Evidence: `apps/capture/src/app.svelte:83-141`.

### Verifier

```bash
cd apps/verifier && pnpm build
# Open dist/verify.html in any browser and drag a .witness file onto the drop zone.
```

The build script asserts that the output contains no external `src`/`href`, no `fetch`, no `XMLHttpRequest`, and no `importScripts` before considering the build successful.
Evidence: `apps/verifier/build.mjs:55-75`.

## Configuration

| Item | Source | Default | Where it is read |
| :--- | :--- | :--- | :--- |
| Sidecar endpoint | `--endpoint` CLI flag | `http://127.0.0.1:8080` | `crates/witness-inference/src/http.rs` (`DEFAULT_ENDPOINT`) |
| Sidecar model id | `GW_SIDECAR_MODEL` env | varies per sidecar | `inference/*/start.sh` |
| Sidecar host / port | `GW_SIDECAR_HOST`, `GW_SIDECAR_PORT` | `127.0.0.1`, `8080` | `inference/*/start.sh` |
| Keyring service | constant | `tech.aftermath.gemma-witness` | `crates/witness-core/src/keystore.rs:19` |
| Keyring account | constant | `device-signing-key-v1` | `crates/witness-core/src/keystore.rs:21` |
| Manifest schema version | constant | `1` | `crates/witness-core/src/manifest.rs:17` |
| Known fingerprints | JSON inlined into verifier | `apps/verifier/known-fingerprints.json` | `apps/verifier/build.mjs:37-47` |
| Capture model fingerprint | JSON | `inference/mlx-sidecar/model-fingerprint.json` | `apps/capture/src-tauri/src/commands/seal_commands.rs:102-103` |
| Audio target rate | constant | `16000 Hz`, mono | `apps/capture/src-tauri/src/audio.rs:19` |
| Recording cap | constant | `30 s` | `apps/capture/src-tauri/src/audio.rs:21` |

A `.env.example` is included in the repo root for reference. The capture app and library code do not currently `dotenv::dotenv()`-load this file; it is a documentation artifact for sidecar scripts and `RUST_LOG`.

## Development

### Test

```bash
# All Rust unit + integration tests
cargo test --workspace -- --test-threads=1

# Specific suites that do not need a running sidecar
cargo test -p witness-core --test bundle_roundtrip
cargo test -p witness-core --test canonicalization
cargo test -p witness-core --test keystore
cargo test -p witness-core --test incident_schema

# Live end-to-end test against a running sidecar (skips gracefully if absent)
cargo test -p witness-core --test day-4-e2e -- --nocapture

# Verifier end-to-end (7 cases including signature flip, byte tamper, canonical reordering)
cd apps/verifier && pnpm install && pnpm build && npx tsx tests/e2e.test.ts
```

Verifier tests pass locally (verified during this audit, `=== ALL E2E TESTS PASSED ===`). Rust tests were not executed during this audit because the toolchain is not installed on the audit host; CI on `macos-latest` is the reference run.

### Lint, format, coverage

```bash
cargo fmt -- --check
cargo clippy --workspace --all-targets -- -D warnings
cd apps/verifier && pnpm lint     # tsc --noEmit
cd apps/capture && pnpm lint      # tsc --noEmit + svelte-check

# Coverage (Rust, used by CI)
cargo tarpaulin --workspace --out Html --out Xml -- --test-threads=1
```

### Regenerate Tauri bindings

```bash
cd apps/capture/src-tauri && cargo test export_bindings -- --nocapture
# writes apps/capture/src/bindings.ts via tauri-specta
```

### CI

`.github/workflows/ci.yml` runs five jobs on push and pull request:

1. `rust-checks` (macOS): fmt, clippy with `-D warnings`, build, single-threaded tests.
2. `rust-coverage` (macOS): tarpaulin, uploads HTML + Cobertura XML as an artifact.
3. `verifier-js` (Ubuntu): pnpm install, lint, build, e2e tests.
4. `rust-e2e-degraded` (macOS): exercises the skip path of `day-4-e2e` plus the offline Rust suites.
5. `em-dash-scan` (Ubuntu): hard-fails on `\u2014` in any source file.

## Repository health findings

These are real findings from the audit. They are not blockers for development but they are blockers for trusting bundles produced today.

1. **Circular fingerprint seed.** `apps/verifier/known-fingerprints.json` contains a self-declared warning that the only entry was extracted from a fixture bundle signed by the same app that produced it. It proves the verifier plumbing works; it does not provide independent trust. Re-seed from the upstream `mlx-community/gemma-4-e4b-it-4bit` `.safetensors` hash before treating verification as authoritative.

2. **Placeholder fingerprint in mistralrs sidecar.** `inference/mistralrs-sidecar/model-fingerprint.json` ships with `"COMPUTE_ON_FIRST_RUN: ..."` as the SHA-256. Until `compute-fingerprint.sh` runs, the file is unusable.

3. **Hard-coded fingerprint path in the seal command.** `seal_bundle_cmd` always reads `inference/mlx-sidecar/model-fingerprint.json` (`apps/capture/src-tauri/src/commands/seal_commands.rs:102-103`). On Linux or Windows, where mistralrs or transformers would run, the sealed manifest will still record the MLX fingerprint. This is a correctness bug for non-Apple paths.

4. **Live end-to-end test cannot run in CI.** `crates/witness-core/tests/day-4-e2e.rs` is wired to skip with a printed message when the sidecar is unreachable. CI runs the skip path only. Live coverage exists in `apps/verifier/tests/e2e.test.ts` against a committed fixture, but the Rust-side live pipeline is not exercised by CI.

5. **No lockfile for the capture frontend.** `apps/capture/` has `package.json` but no `pnpm-lock.yaml`. JS dependency resolution is non-reproducible for the capture app. The verifier directory does have a lockfile and is reproducible.

6. **Cross-platform paths are scripted but unverified.** `mistralrs-sidecar/start.sh` and `transformers-sidecar/start.py` exist and look correct on inspection, but there are no fixtures, CI lanes, or evidence files demonstrating an end-to-end capture on Linux or Windows.

7. **Software-only key custody.** Keys live in the OS keychain (macOS Keychain, Secret Service on Linux, Credential Manager on Windows via the `keyring` crate). There is no TPM, Secure Enclave, or hardware attestation. A compromised user account can sign arbitrary bundles. This is documented as a TOFU model and is intentional for the current scope.

8. **No external trust anchor.** The verifier checks the signature against the public key embedded in the manifest. Provenance of the device key is not currently anchored to any external CA, transparency log, or registry. Two devices can produce bundles signed by completely independent keys and both will verify against the verifier; trust in the signer is out of scope of the current code.

9. **Reasoning trace parsing assumption.** `inference/transformers-sidecar/start.py:178-181` extracts the reasoning channel with a regex on `"\n\nReasoning process:\n..."`. If the model output format changes, the trace will be silently captured as part of `content` instead. The Apple Silicon and mistralrs paths use different extraction logic; behavior is not bit-identical across sidecars.

10. **Audio passed to sidecar as a file path marker, not raw audio.** The transformers sidecar accepts `input_audio` as a path string and emits `[Audio file: <path>]` into the prompt rather than streaming audio bytes to the model (`inference/transformers-sidecar/start.py:81-87`). The "multimodal" label in this repo therefore refers to text + images plus a text-described audio transcript pass, not to direct raw-audio attention. The architecture has the four-pass transcribe step explicitly because of this.

11. **Model identifier "Gemma 4 E4B" is referenced as if it exists on Hugging Face.** The code, scripts, and documentation refer to `google/gemma-4-E4B-it` and `mlx-community/gemma-4-e4b-it-4bit`. This audit did not connect to the network and cannot confirm that those identifiers resolve. If they do not exist or have been renamed, every sidecar startup will fail.

## Reality check

**Proven during this audit**

- The verifier builds to a 29,417-byte single HTML file with no external references, no `fetch`, no `XMLHttpRequest`, no `importScripts` (asserted by `build.mjs` and re-verified here).
- The verifier passes all 7 end-to-end cases including positive verification, audio byte flip, signature corruption, unknown fingerprint, manifest key reordering, and unknown manifest_version.
- The bundle format is fully specified (`spec/bundle-format.md`, `spec/manifest-schema.json`, `spec/incident-schema.json`) and the Rust types match the schemas.
- The CI workflow exists and is well-formed YAML covering fmt, clippy, build, test, coverage, verifier, and an em-dash gate.
- TypeScript bindings are generated by `tauri-specta` and committed at `apps/capture/src/bindings.ts`.

**Assumed but not executed during this audit**

- Rust workspace builds and tests pass. The toolchain is not present on this audit host; CI is the reference. The code reads as internally consistent.
- The Apple Silicon path works end-to-end on a real M-series machine with `mlx-vlm` installed.

**Not verified, deliberately**

- That Hugging Face actually hosts the referenced Gemma 4 E4B repositories.
- That the mistralrs and transformers paths produce bit-compatible reasoning traces with the MLX path.
- Throughput, memory footprint, and latency on any specific hardware.

## Contributing

The codebase has stronger-than-usual style and correctness rules. Skim these before opening a PR.

- `CLAUDE.md` documents project conventions: no `unwrap()` in non-test Rust, no `any` in TypeScript, no default exports, kebab-case TypeScript filenames, snake_case Rust modules, named exports only, 300-line file limit, JSDoc on exported TS functions, full `///` doc comments on Rust public items, no em dashes anywhere, including commit messages.
- `.github/copilot-instructions.md` mirrors those rules and adds the project invariants: signature covers JCS-canonicalized bytes, asset hashes are over raw bytes, reasoning trace is captured verbatim, private keys never leave the keychain.
- All changes that touch `crates/witness-core` or the manifest schema must keep the `MANIFEST_VERSION` constant and `spec/manifest-schema.json` in lockstep, and must keep the round-trip test green.
- Commits follow conventional commits (`feat:`, `fix:`, `docs:`, `chore:`, `test:`, `refactor:`, `style:`).
- CI enforces `cargo fmt`, `cargo clippy -D warnings`, verifier `tsc --noEmit`, and the em-dash scan.

## License

MIT. See [LICENSE](LICENSE).
