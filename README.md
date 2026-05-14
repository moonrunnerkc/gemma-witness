<p align="center">
  <img src="docs/cover.svg" alt="Gemma.Witness: offline, multimodal, tamper-evident evidence capture" width="100%">
</p>

<h1 align="center">Gemma.Witness</h1>

<p align="center">
  Offline multimodal evidence capture that emits a signed, locally verifiable bundle.
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-7dd3fc?style=flat-square"></a>
  <img alt="Rust 1.80+" src="https://img.shields.io/badge/rust-1.80%2B-1a2548?style=flat-square&logo=rust&logoColor=ffffff">
  <img alt="Node 22" src="https://img.shields.io/badge/node-22.x-1a2548?style=flat-square&logo=node.js&logoColor=ffffff">
  <img alt="Tauri 2" src="https://img.shields.io/badge/tauri-2.x-1a2548?style=flat-square&logo=tauri&logoColor=ffffff">
  <img alt="Status: pre-release" src="https://img.shields.io/badge/status-pre--release-a78bfa?style=flat-square">
</p>

---

## Status

This is a pre-release research project.

The full capture and verification chain is designed to run offline, but the current implementation still has important trust and portability limitations. Read the [limitations](#current-limitations) section before relying on it for real-world evidence handling.

## What it does

Gemma.Witness records:

- audio
- images
- structured incident metadata

It then runs a local Gemma-based multimodal pipeline that:

- transcribes audio
- structures the incident
- analyzes images
- checks cross-modal consistency

The resulting evidence bundle includes:

- captured assets
- structured report
- reasoning trace
- manifest
- signature
- public verification key

Bundles are written as deterministic `.witness` ZIP archives and signed with an Ed25519 device key stored in the operating system keychain.

A separate static HTML verifier:

- runs fully offline
- validates signatures
- recomputes hashes
- checks bundle integrity
- validates pinned model fingerprints

No network access is required for verification.

## Architecture

```
Capture App (Tauri 2)
        │
        ▼
Local inference sidecar
        │
        ▼
Signed .witness bundle
        │
        ▼
Offline HTML verifier
```

The repository includes:

- a desktop capture application
- multiple local inference sidecars
- a Rust core library
- a static verifier
- a CLI pipeline
- evaluation tooling

### Execution flow

1. Record audio and select images
2. Run the local four-pass inference pipeline
3. Review the generated report
4. Seal the evidence bundle
5. Verify hashes, signatures, and fingerprints offline

The signing payload uses RFC 8785 JCS canonicalization before Ed25519 signing.

## Repository layout

| Path | Purpose |
| :--- | :--- |
| `crates/witness-core` | Canonicalization, hashing, signing, verification, bundle generation |
| `crates/witness-inference` | Four-pass inference pipeline |
| `crates/witness-cli` | Headless CLI pipeline |
| `crates/witness-eval` | Evaluation harness |
| `apps/capture` | Tauri capture application |
| `apps/verifier` | Static offline verifier |
| `inference/mlx-sidecar` | Apple Silicon inference path |
| `inference/mistralrs-sidecar` | Cross-platform Rust inference path |
| `inference/transformers-sidecar` | Python fallback inference path |

## Implemented features

Current implementation includes:

- offline capture workflow
- multimodal four-pass pipeline
- OpenAI-compatible inference sidecars
- structured incident extraction
- reasoning trace capture
- RFC 8785 JCS canonicalization
- Ed25519 signing and verification
- deterministic ZIP generation
- static offline verifier
- verifier integrity checks
- model fingerprint pinning
- Rust round-trip verification tests
- GitHub Actions CI
- coverage reporting
- evaluation tooling

Cross-platform live capture remains partially unverified outside the Apple Silicon path.

## Installation

### Prerequisites

| Requirement | Notes |
| :--- | :--- |
| Rust 1.80+ | Workspace MSRV |
| Node 22 | Used by verifier and capture frontend |
| pnpm 9 | Used in CI |
| Python 3.13 | Required for mlx-sidecar |
| Apple Silicon | Required for mlx-vlm path |

### Build

From the repository root:

```bash
cargo build --workspace
```

Build the verifier:

```bash
cd apps/verifier
pnpm install --frozen-lockfile
pnpm build
cd -
```

Install capture app dependencies:

```bash
cd apps/capture
pnpm install
```

> Note: `apps/capture` currently does not include a committed lockfile.

### Inference sidecars

Choose one inference backend.

Apple Silicon (primary path):

```bash
./inference/mlx-sidecar/start.sh
```

mistralrs:

```bash
./inference/mistralrs-sidecar/start.sh
./inference/mistralrs-sidecar/compute-fingerprint.sh
```

Transformers fallback:

```bash
cd inference/transformers-sidecar
pip install -r requirements.txt
python start.py
```

All sidecars expose an OpenAI-compatible API on `127.0.0.1:8080`.

## Usage

### CLI pipeline

Structure-only pass:

```bash
cargo run -p witness-cli -- structure \
  --transcript tests/fixtures/day1-sample.txt
```

Full pipeline:

```bash
cargo run -p witness-cli -- pipeline \
  --audio tests/fixtures/day-3-scenarios/1/audio.wav \
  --image tests/fixtures/day-3-scenarios/1/image1.jpg \
  --image tests/fixtures/day-3-scenarios/1/image2.jpg
```

### Capture app

```bash
cd apps/capture
pnpm tauri dev
```

Workflow:

1. record
2. attach images
3. run inference
4. review
5. seal

### Verifier

```bash
cd apps/verifier
pnpm build
```

Open `dist/verify.html`, then drag a `.witness` bundle into the verifier.

The verifier build fails if the generated HTML contains:

- external network references
- `fetch`
- `XMLHttpRequest`
- `importScripts`

## Configuration

| Item | Default |
| :--- | :--- |
| Sidecar endpoint | `http://127.0.0.1:8080` |
| Audio format | 16 kHz mono WAV |
| Recording cap | 30 seconds |
| Manifest schema version | `1` |
| Key service | `tech.aftermath.gemma-witness` |

A `.env.example` file is included for reference.

## Development

### Tests

Run all Rust tests:

```bash
cargo test --workspace -- --test-threads=1
```

Verifier end-to-end tests:

```bash
cd apps/verifier
pnpm install
pnpm build
npx tsx tests/e2e.test.ts
```

Live end-to-end sidecar test:

```bash
cargo test -p witness-core --test day-4-e2e -- --nocapture
```

The live test skips automatically if no sidecar is reachable.

### Lint and coverage

```bash
cargo fmt -- --check
cargo clippy --workspace --all-targets -- -D warnings

cd apps/verifier && pnpm lint
cd apps/capture && pnpm lint
```

Coverage:

```bash
cargo tarpaulin --workspace --out Html --out Xml -- --test-threads=1
```

### CI

GitHub Actions currently runs:

- Rust build and test
- clippy with `-D warnings`
- coverage generation
- verifier end-to-end tests
- degraded-path Rust tests
- em-dash scan enforcement

## Current limitations

These are real limitations in the current implementation.

### Trust model limitations

- Keys are software-held in the OS keychain only.
- No TPM, Secure Enclave, or hardware attestation.
- No external certificate authority or transparency log.
- Verification currently operates as a TOFU-style trust model.

A compromised user account can sign arbitrary bundles.

### Fingerprint limitations

The current verifier fingerprint seed is self-derived from fixture output and should not yet be treated as an authoritative trust anchor.

The mistralrs sidecar also ships with a placeholder fingerprint until:

```bash
./compute-fingerprint.sh
```

is executed.

### Cross-platform gaps

The Apple Silicon path is the primary tested implementation.

Linux and Windows inference paths exist, but currently lack:

- full fixture coverage
- CI validation
- verified end-to-end capture evidence

### Capture correctness issue

`seal_bundle_cmd` currently hardcodes the MLX fingerprint path during sealing.

On Linux or Windows paths, bundles may incorrectly record the Apple Silicon fingerprint.

### CI limitations

The live sidecar pipeline is not exercised in CI.

Current CI validates:

- offline verifier behavior
- fixture integrity
- Rust verification logic

but not a full live capture-to-seal pipeline.

### Reproducibility gaps

`apps/capture` does not currently include a committed `pnpm-lock.yaml`.

Frontend dependency resolution for the capture app is therefore not fully reproducible.

### Audio model limitations

The transformers fallback path does not stream raw audio directly into the model.

Audio is first transcribed, then referenced as text during later passes.

The repository's "multimodal" behavior currently means:

- transcript-derived text
- images
- structured reasoning

not direct raw-audio attention.

## What you can verify yourself

The repository is structured so most claims can be checked locally.

Build the offline verifier:

```bash
cd apps/verifier
pnpm install
pnpm build
```

Run verifier end-to-end tests:

```bash
npx tsx tests/e2e.test.ts
```

Run Rust verification suites:

```bash
cargo test --workspace
```

Inspect the wire format directly:

```bash
cat spec/bundle-format.md
cat spec/manifest-schema.json
cat spec/incident-schema.json
```

Performance and latency characteristics are hardware-dependent and are not benchmarked in this repository.

## Contributing

Project rules are intentionally strict.

Key conventions:

- no `unwrap()` outside tests
- no TypeScript `any`
- no default exports
- kebab-case TypeScript filenames
- snake_case Rust modules
- no em dashes
- conventional commits required

Important invariants:

- signatures cover JCS-canonicalized bytes
- asset hashes are computed from raw bytes
- reasoning traces are stored verbatim
- private keys never leave the keychain

See:

- [`CLAUDE.md`](CLAUDE.md)
- [`.github/copilot-instructions.md`](.github/copilot-instructions.md)

## License

MIT. See [LICENSE](LICENSE).
