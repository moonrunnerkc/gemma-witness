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

## Computing the model fingerprint

After the model is first downloaded, compute the SHA-256 fingerprint so the verifier can pin it:

```bash
./compute-fingerprint.sh
```

This locates the `.safetensors` file in the Hugging Face cache, hashes it, and writes the result into `model-fingerprint.json`.

## OpenAI-compatible surface

Like the `mlx-vlm` sidecar, `mistralrs serve` exposes the same OpenAI-compatible HTTP endpoints:

- `GET /v1/models`
- `POST /v1/chat/completions`

The capture app talks to `http://127.0.0.1:8080` regardless of which sidecar is running, so switching between `mlx-vlm` (Apple Silicon) and `mistralrs` (cross-platform) requires no code changes on the Rust side.

## Cross-platform support

mistral.rs runs on Linux, macOS, and Windows. `--isq 4` enables 4-bit in-place quantization, which keeps memory usage low enough for consumer GPUs and large unified-memory Apple Silicon machines.
