# transformers sidecar

Pure-Python fallback inference sidecar for Gemma 4 E4B using Hugging Face Transformers and FastAPI.

Use this when the Apple Silicon `mlx-vlm` path or the `mistralrs` path is unavailable.

## Setup

Install dependencies into a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Or use `uv`:

```bash
uv pip install -r requirements.txt
```

## Starting the sidecar

```bash
python3 start.py --model google/gemma-4-E4B-it --host 127.0.0.1 --port 8080
```

The server loads the model on first startup (this may take several minutes while weights are downloaded or cached).

## API

The sidecar exposes the same OpenAI-compatible endpoints as the other sidecars:

- `GET /v1/models`
- `POST /v1/chat/completions`

### Supported inputs

- Text messages
- Images via `image_url` with base64 data URI or local file path
- Audio file paths via `input_audio` content parts (treated as a text marker; Gemma 4 does not process raw audio natively in this fallback)
- Tool definitions via the `tools` parameter (injected into the prompt; the model outputs JSON that is parsed into `tool_calls`)

### Sampling parameters

Pass standard OpenAI fields in the request body:

- `temperature`
- `max_tokens`
- `top_p`

## Notes

- `device_map="auto"` is used so the model loads onto the best available accelerator (CUDA, MPS, or CPU).
- `bfloat16` is used when a CUDA device is present; otherwise `float32` is used for CPU compatibility.
