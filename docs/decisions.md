# Decisions Log

One-line entries acceptable. The goal is auditability of non-trivial choices.

## Day 1

- Python toolchain: managed by `uv` (0.11.x), pinning CPython 3.13.13 under `inference/mlx-sidecar/`. Matches build-guide guidance and CLAUDE.md stack table.
- Package manifest: `pyproject.toml` (PEP 621) rather than `requirements.txt`, because `uv` resolves and locks via `uv.lock` automatically and `pyproject.toml` is the idiomatic Python project metadata for uv-managed projects.
- Dependencies pinned: `mlx-vlm` and `torchvision`, exact resolved versions recorded in `uv.lock` and echoed in `evidence/day1/MANIFEST.md`.
- Model: `mlx-community/gemma-4-e4b-it-4bit`. Revision SHA captured in `inference/mlx-sidecar/model-fingerprint.json` at the time of first pull.
- Fixture text: a short fixed-content sentence generated with macOS `say` and converted to 16 kHz mono PCM WAV via `afconvert`. The fixture is deterministic for the same `say` voice and afconvert flags. Reference text saved alongside as `day1-sample.txt`.
- Prompt wording: `"Transcribe this audio"`. Verbatim from the build guide so the sidecar exercise matches the documented invocation.
- Sidecar request shape: OpenAI-compatible `/v1/chat/completions` with a multimodal user message containing an `input_audio` content part (base64-encoded WAV + format hint). Exact verified shape recorded under the "Sidecar request shape" entry below once probed.
- Process model: `start.sh` launches the sidecar with `nohup`, writes the PID to `evidence/day1/sidecar.pid`, and logs to `evidence/day1/sidecar.log`. `stop.sh` reads the PID file and signals the process.

### Sidecar request shape (verified)

Verified against `mlx-vlm==0.5.0` server on 2026-05-10. The OpenAI-compatible endpoint is `POST /v1/chat/completions`. Body shape:

```json
{
  "model": "mlx-community/gemma-4-e4b-it-4bit",
  "max_tokens": 500,
  "temperature": 0.0,
  "messages": [
    {
      "role": "user",
      "content": [
        {"type": "input_text", "text": "Transcribe this audio"},
        {"type": "input_audio", "input_audio": {"data": "<absolute path or http url>", "format": "wav"}}
      ]
    }
  ]
}
```

Quirk: at version 0.5.0 the mlx-vlm server passes `input_audio.data` straight to `mlx_vlm.utils.load_audio`, which only accepts a filesystem path or an http(s) URL, not the base64 string the OpenAI spec normally uses for `input_audio`. The CLI sends an absolute local path. This is acceptable because the capture app and sidecar are colocated on the same host. If a future mlx-vlm release accepts base64 (or a `data:` URL), revisit `inference/mlx-sidecar/cli/transcribe.py::build_request_body`.

Reproduction command:

```
curl -sf -X POST http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  --data @/tmp/req.json
```

Resolved Python package versions for the sidecar are captured in `evidence/day1/python-versions.txt`.

### Smoke-test assertion

The smoke test asserts the lowercased, whitespace-collapsed transcript contains the substring `"witness arrived at the corner of main street"`. This is a stable head-of-utterance phrase from the fixture's reference text and was chosen because it survives Gemma's normalization (date and time numerics get rendered as `4:47` / `October 14th, 2025`, but the leading clause stays verbatim). Per CLAUDE.md, inference tests never assert on exact strings; this is a substring check on a deterministic prefix.
