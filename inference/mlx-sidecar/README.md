# mlx-vlm sidecar

OpenAI-compatible inference sidecar backed by `mlx-vlm` for Apple Silicon. The
capture app calls this over `http://127.0.0.1:8080`.

## Supported install path

`uv sync` is the only supported install path. The `uv.lock` in this directory
pins every wheel (including transitive deps) by SHA-256.

```sh
cd inference/mlx-sidecar
uv sync
./start.sh
```

Do not run `pip install -e .` against this directory. `pyproject.toml` carries
upper-bounded ranges so a hand-installed environment can stay within the same
minor as the lockfile, but the hashed pin lives only in `uv.lock`.

## Environment

| Variable | Default | Notes |
|---|---|---|
| `GW_SIDECAR_MODEL` | `mlx-community/gemma-4-e4b-it-4bit` | Must match a row in `inference/fingerprints/index.json`. |
| `GW_SIDECAR_PORT` | `8080` | The capture app's default. |
| `GW_SIDECAR_HOST` | `127.0.0.1` | `start.sh` refuses any non-loopback host. |
| `GW_SIDECAR_TOKEN` | (set by capture app) | Per-launch shared secret. The capture app spawns the sidecar with this env var; manual launches without it accept any request and should not be trusted by the capture app. |

## stop.sh

`./stop.sh` reads the PID file written by `start.sh` and signals the process.
