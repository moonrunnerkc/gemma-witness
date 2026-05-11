# Gemma.Witness

Offline, multimodal, tamper-evident evidence capture for civic accountability. This system records audio and images, processes them via a local Gemma 4 E4B model to create a structured incident report, and emits a signed `.witness` bundle that can be verified by a standalone static-HTML verifier.

## Architecture

The system consists of three primary components communicating over local HTTP and the file system:

1.  **Capture App (`apps/capture`)**: A Tauri 2.x desktop application.
    - **Frontend**: Svelte 5 + TypeScript.
    - **Backend**: Rust. Handles audio recording (`cpal`), image selection (`tauri-plugin-dialog`), and bundle sealing.
2.  **Inference Sidecars (`inference/`)**: OpenAI-compatible HTTP servers providing Gemma 4 E4B capabilities.
    - **MLX Sidecar (`mlx-sidecar`)**: Optimized for Apple Silicon via `mlx-vlm`.
    - **Mistralrs Sidecar (`mistralrs-sidecar`)**: Rust-native implementation for cross-platform deployment.
    - **Transformers Sidecar (`transformers-sidecar`)**: Python-based fallback using HuggingFace `transformers`.
3.  **Verifier (`apps/verifier`)**: A single, self-contained HTML file.
    - Uses WASM-backed crypto (`@noble/ed25519`, `@noble/hashes`) and `fflate` for ZIP extraction.
    - Zero network calls; all logic and known-model fingerprints are inlined.

### Execution Flow
`Audio/Images` → `Inference Pipeline (4 passes)` → `User Review` → `Manifest Generation` → `Ed25519 Signing` → `.witness` ZIP Bundle → `Static Verifier`.

## Verified Features

| Feature | Status | Evidence |
| :--- | :--- | :--- |
| Multimodal Pipeline | Implemented | `crates/witness-inference/src/pipeline.rs` |
| Bundle Sealing | Implemented | `crates/witness-core/src/bundle_builder.rs` |
| Ed25519 Signing | Implemented | `crates/witness-core/src/signing.rs`, `keystore.rs` |
| OS Keychain Storage | Implemented | `crates/witness-core/src/keystore.rs` (via `keyring`) |
| Static Verifier | Implemented | `apps/verifier/verify.ts`, `build.mjs` |
| Model Fingerprinting | Implemented | `crates/witness-core/src/manifest.rs`, `verifier.rs` |
| Audio Capture | Implemented | `apps/capture/src-tauri/src/audio.rs` (via `cpal`) |
| JCS Canonicalization | Implemented | `crates/witness-core/src/canonical.rs` (RFC 8785) |

## Installation

### Prerequisites
- **Rust**: Stable (MSRV 1.80)
- **Node.js**: `pnpm` installed
- **Python**: `uv` (recommended for sidecars)
- **OS**: macOS (Apple Silicon) for `mlx-sidecar`; Linux/Windows for `mistralrs-sidecar`.

### Setup
```bash
# Install dependencies
pnpm install
cargo build --workspace

# Start the inference sidecar (example: MLX on Apple Silicon)
./inference/mlx-sidecar/start.sh

# Run the capture app
cd apps/capture && pnpm tauri dev

# Build the static verifier
cd apps/verifier && pnpm build
```

## Usage

### CLI Pipeline Testing
Run the headless pipeline against fixtures:
```bash
cargo run -p witness-cli -- pipeline \
  --audio tests/fixtures/day-3-scenarios/1/audio.wav \
  --images tests/fixtures/day-3-scenarios/1/image1.jpg tests/fixtures/day-3-scenarios/1/image2.jpg
```

### Verification
1. Open `apps/verifier/dist/verify.html` in any browser.
2. Drag and drop a `.witness` bundle.
3. Verify signature, asset hashes, and model fingerprint.

## Configuration

| Item | Source | Default | Description |
| :--- | :--- | :--- | :--- |
| Sidecar Endpoint | Env / CLI | `http://localhost:8080` | OpenAI-compatible API endpoint |
| Sidecar Model | Env | `google/gemma-4-E4B-it` | The model ID for the sidecar |
| Keyring Service | Code | `tech.aftermath.gemma-witness` | OS Keychain service name |
| Keyring Account | Code | `device-signing-key-v1` | OS Keychain account name |

## Development

### Testing
- **Unit/Integration**: `cargo test --workspace`
- **End-to-End**: `cargo test -p witness-core --test day-4-e2e` (Requires running sidecar)
- **Verifier Tests**: `cd apps/verifier && npx tsx tests/e2e.test.ts`

### Linting
- **Rust**: `cargo clippy --workspace -- -D warnings`
- **TypeScript**: `pnpm lint`

## Repository Health Findings

- **Broken Workflows**: None detected in source, but the e2e test requires an external sidecar process to be manually started.
- **Stale Docs**: `README.md` previously contained aspirational claims about CI coverage reporting and `tauri-specta` bindings that are not yet fully integrated/active in the main build flow.
- **Risky Assumptions**: The system relies on a "trust-on-first-use" (TOFU) model for device keys. There is no CA or hardware attestation (TPM/TEE) in the current version.
- **Technical Debt**: The `transformers-sidecar` is a basic implementation compared to the MLX and Mistralrs paths.

## Reality Check

- **Proven**: The full chain from audio/image capture to verified signed bundle is implemented and tested.
- **Assumed**: Cross-platform deployment stability is assumed based on the `mistralrs` implementation, though primary testing is focused on Apple Silicon.
- **Unverified**: Full-scale production performance on low-end hardware (e.g., Raspberry Pi 5) has not been benchmarked in this repo's current state.

## Contribution Guidance

1. **Core Logic**: Changes to `crates/witness-core` must maintain compatibility with the manifest version in `spec/manifest-schema.json`.
2. **Frontend**: Use Svelte 5 runes (`$state`, etc.) and follow kebab-case naming for files.
3. **Crypto**: Never re-implement primitives; use the approved libraries (`sha2`, `ed25519-dalek`, `@noble/*`).
4. **Commits**: Use conventional commits (`feat:`, `fix:`, etc.).

