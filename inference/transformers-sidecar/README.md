# transformers sidecar

Pure-Python fallback inference sidecar for Gemma 4 E4B using Hugging Face
Transformers and FastAPI.

Use this when the Apple Silicon `mlx-vlm` path or the `mistralrs` path is
unavailable.

## Supported install path

`uv sync` is the only supported install path. `pyproject.toml` carries
upper-bounded ranges; the `uv.lock` generated on a release host pins every
wheel by SHA-256.

```bash
cd inference/transformers-sidecar
uv sync
```

If `uv.lock` is missing in your checkout (it is regenerated on the release
host as part of the release flow), run `uv lock` once to materialize it. CI
then enforces `uv sync --frozen`.

Do not `pip install` against an unpinned `requirements.txt`; the previous
unpinned `requirements.txt` has been removed and replaced by `pyproject.toml`
to close the "PyPI typo-squat lands on the sidecar process" supply-chain gap.

## Starting the sidecar

```bash
uv run python start.py --model google/gemma-4-E4B-it --host 127.0.0.1 --port 8080
```

The server loads the model on first startup (this may take several minutes
while weights are downloaded or cached).

The sidecar refuses to bind to any non-loopback host. See `start.py` for the
allowlist.

## API

The sidecar exposes the same OpenAI-compatible endpoints as the other sidecars:

- `GET /v1/models`
- `POST /v1/chat/completions`

### Supported inputs

- Text messages
- Images via `image_url` with base64 data URI or local file path
- Audio via `input_audio` content parts. The sidecar reads the bytes (path or
  data URI), resamples to 16 kHz mono float32 in memory using torchaudio, and
  passes the waveform to the processor under the `audio=` kwarg of
  `apply_chat_template`. The on-disk bytes that the manifest hashes are not
  modified.
- Tool definitions via the `tools` parameter (injected into the prompt; the
  model outputs JSON that is parsed into `tool_calls`)

### Sampling parameters

Pass standard OpenAI fields in the request body:

- `temperature`
- `max_tokens`
- `top_p`

## Notes

- `device_map="auto"` is used so the model loads onto the best available
  accelerator (CUDA, MPS, or CPU).
- `bfloat16` is used when a CUDA device is present; otherwise `float32` is
  used for CPU compatibility.

## Tests

`tests/test_boot_handshake.py` is the per-PR Linux gate. It uses FastAPI's
`TestClient` to confirm the sidecar's HTTP surface boots, that `start.py`
imports without raising, and that `/v1/models` returns the expected
OpenAI-compatible envelope. The tests deliberately do NOT load the model
weights, so they run in seconds without HF authentication and without GPU
access. Full inference is exercised in the live-e2e workflow on hardware
that can host the gated `google/gemma-4-E4B-it` weights.

```bash
uv sync
uv run pytest tests/ -v
```
