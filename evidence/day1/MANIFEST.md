# Day 1 Evidence Manifest

End-of-day deliverable: WAV in, accurate English text out, sidecar reachable on `http://127.0.0.1:8080`, plus a CLI script that posts a WAV and prints the transcript.

Captured 2026-05-10 on MacBook Pro M5 Max, 64GB unified memory, macOS, Apple Silicon, Python 3.13.13 via `uv` 0.11.13.

| Gate | Status | Evidence | Summary | Command |
| --- | --- | --- | --- | --- |
| 1. Repo skeleton seeded | PASS | `.gitignore`, `README.md`, `docs/decisions.md`, plus empty placeholder dirs `apps/{capture,verifier}`, `crates/{witness-core,witness-cli,witness-inference}`, `spec/`, `tests/{fixtures,e2e,day1}`, and populated `inference/mlx-sidecar/` | Directory layout matches `CLAUDE.md` "Project structure" section; Tauri, crates, and verifier are placeholders only. | `mkdir -p ...` (see commit `chore: initial repo skeleton and gitignore`) |
| 2. Python environment | PASS | `inference/mlx-sidecar/pyproject.toml`, `inference/mlx-sidecar/uv.lock`, `evidence/day1/python-versions.txt` | `uv`-managed CPython 3.13.13 venv with `mlx-vlm==0.5.0`, `mlx==0.31.2`, `mlx-audio==0.4.3`, `mlx-lm==0.31.3`, `torchvision==0.26.0`, `transformers==5.8.0`, `fastapi==0.136.1`, `uvicorn==0.46.0`, `requests==2.33.1`, `miniaudio==1.71`. | `cd inference/mlx-sidecar && uv sync` |
| 3. Model pulled and cached | PASS | `inference/mlx-sidecar/model-fingerprint.json` | `mlx-community/gemma-4-e4b-it-4bit` revision `cc3b666c01c20395e0dcebd53854504c7d9821f9`. SHA-256 of `model.safetensors` (5,217,361,182 bytes): `339409bd18494955556e1fde6ccc15faaa9f707b911b74791fe290b9d722beed`. | `uv run python -c "from huggingface_hub import snapshot_download; snapshot_download('mlx-community/gemma-4-e4b-it-4bit')"` then sha256 walk |
| 4. Test fixture | PASS | `tests/fixtures/day1-sample.wav` (16 kHz mono PCM WAV, 13.49 s, 149,004 bytes), `tests/fixtures/day1-sample.txt` (reference text) | Deterministic narration synthesized with macOS `say -v Samantha -r 165` and converted to 16 kHz mono 16-bit PCM WAV with `afconvert`. | `say -v Samantha -r 165 -o /tmp/day1.aiff "$REF" && afconvert -f WAVE -d LEI16@16000 -c 1 /tmp/day1.aiff tests/fixtures/day1-sample.wav` |
| 5. CLI generate check | PASS | `evidence/day1/cli-generate.log` | `mlx_vlm generate` transcribes the fixture word-for-word; substring `"witness arrived at the corner of main street"` and `"oak avenue"` and `"tuesday"` all present (case-insensitive). | `uv run --project inference/mlx-sidecar python -m mlx_vlm generate --model mlx-community/gemma-4-e4b-it-4bit --audio tests/fixtures/day1-sample.wav --prompt "Transcribe this audio" --max-tokens 500` |
| 6. Sidecar running | PASS | `evidence/day1/sidecar.pid` (writes process id), `evidence/day1/sidecar.log` (stdout/stderr capture), `inference/mlx-sidecar/start.sh`, `inference/mlx-sidecar/stop.sh` | `start.sh` launches `mlx_vlm server` via `nohup`, writes the PID, then polls `GET /v1/models` until ready (240 s deadline) before returning. `stop.sh` reads the PID file and signals SIGTERM (SIGKILL after 10 s). | `./inference/mlx-sidecar/start.sh` |
| 7. Sidecar curl probe | PASS | `evidence/day1/curl-response.json` | OpenAI-compatible `POST /v1/chat/completions` with multimodal user message containing `{type:"input_audio", input_audio:{data:"<absolute path>", format:"wav"}}` returns HTTP 200 with non-empty assistant content matching the reference. Quirk documented in `docs/decisions.md`: at mlx-vlm 0.5.0, `input_audio.data` is treated as a filesystem path or http URL, not base64. | `curl -sf -X POST http://127.0.0.1:8080/v1/chat/completions -H 'content-type: application/json' --data @/tmp/req.json` |
| 8. CLI deliverable | PASS | `inference/mlx-sidecar/cli/transcribe.py` (185 lines, well under the 300-line cap) | Python CLI with positional WAV path and `--endpoint`, `--prompt`, `--max-tokens`, `--model` flags. Type hints on every function, `pathlib.Path` over strings, no bare `except`, named exports only (no `__all__` magic), docstrings on all public functions. Errors raise `TranscribeError` with what-failed-and-what-to-do messages; non-zero exit on failure. | `uv run --project inference/mlx-sidecar python inference/mlx-sidecar/cli/transcribe.py tests/fixtures/day1-sample.wav` |
| 9. Smoke test | PASS | `evidence/day1/smoke-test.log`, `tests/day1/test-transcribe.sh` | Script invokes the CLI against `tests/fixtures/day1-sample.wav` and asserts the case-insensitive, whitespace-collapsed transcript contains `"witness arrived at the corner of main street"`. Exit code 0. | `./tests/day1/test-transcribe.sh` |
| 10. Evidence manifest | PASS | this file (`evidence/day1/MANIFEST.md`) | Every gate carries a status, evidence path, summary, and reproduction command. | n/a |
| 11. Decisions log | PASS | `docs/decisions.md` | Records toolchain choice (`uv`), package manifest format (`pyproject.toml`), fixture text, prompt wording, sidecar request shape and the mlx-vlm 0.5.0 path-not-base64 quirk, process model (`nohup` + PID file), and smoke-test substring rationale. | n/a |
| 12. Commit | PASS | `git log --oneline` in repo root | Six conventional-commit splits as specified in the prompt. Not pushed. | `git log --oneline -n 6` |

## What this proves end-to-end

1. Gemma 4 E4B 4-bit MLX loads, runs, and accurately transcribes English audio on this hardware (~127 tok/s prefill, ~130 tok/s generation, peak 6 GB unified memory for a 13.5 s clip at 500 max tokens).
2. The mlx-vlm OpenAI-compatible sidecar is reachable at `http://127.0.0.1:8080`, accepts multimodal audio messages, and returns standard `chat.completion` payloads with non-empty content.
3. A Python CLI (the Day 1 deliverable) posts a WAV and prints the transcript, with proper error handling and no inline crypto, network-to-third-party, or capture-app code paths.
4. The build is reproducible: every artifact has a recorded command, every dependency a pinned version, every binary input a recorded SHA-256.

## What this does NOT include (deferred to Day 2+)

- Function calling / structured incident JSON (Day 2).
- Image leg (Day 3).
- Tauri shell, Rust crates, signing, bundle format (Day 4).
- Verifier (Day 5).

No Rust, TypeScript, or Tauri code was created today.
