# mistralrs sidecar

Cross-platform inference sidecar for Gemma 4 E4B using [mistral.rs](https://github.com/EricLBuehler/mistral.rs).

## Installation

Install the `mistralrs` binary using the official install script:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/EricLBuehler/mistral.rs/master/install.sh | sh
```

Or build from source with Cargo:

```bash
cargo install --git https://github.com/EricLBuehler/mistral.rs --locked mistralrs-server
```

Ensure `mistralrs` is on your `PATH`.

## Starting the sidecar

```bash
./start.sh
```

The script reads these environment variables:

| Variable | Default |
|---|---|
| `GW_SIDECAR_MODEL` | `google/gemma-4-E4B-it` |
| `GW_SIDECAR_PORT` | `8080` |
| `GW_SIDECAR_HOST` | `127.0.0.1` |

It launches the server in the background, waits for the `/v1/models` endpoint to respond, and then exits.

To stop:

```bash
./stop.sh
```

## Recording the model fingerprint

Fingerprints are now centralized at `inference/fingerprints/`. After the model is first downloaded, seed the entry for `google/gemma-4-E4B-it@main`:

```bash
cargo run -p seed-fingerprints -- --model-id google/gemma-4-E4B-it --revision main
```

The seeder fetches the Hugging Face LFS oid for that revision, recomputes the SHA-256 of the locally cached `model.safetensors`, refuses to write on mismatch, and updates `inference/fingerprints/google__gemma-4-E4B-it__main.json` along with `apps/verifier/known-fingerprints.json`. The sidecar's `start.sh` refuses to boot against an unseeded entry.

## OpenAI-compatible surface

Like the `mlx-vlm` sidecar, `mistralrs serve` exposes the same OpenAI-compatible HTTP endpoints:

- `GET /v1/models`
- `POST /v1/chat/completions`

The capture app talks to `http://127.0.0.1:8080` regardless of which sidecar is running, so switching between `mlx-vlm` (Apple Silicon) and `mistralrs` (cross-platform) requires no code changes on the Rust side.

## Cross-platform support

mistral.rs runs on Linux, macOS, and Windows. `--isq 4` enables 4-bit in-place quantization, which keeps memory usage low enough for consumer GPUs and large unified-memory Apple Silicon machines.
