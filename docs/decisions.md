# Decisions Log

One-line entries acceptable. The goal is auditability of non-trivial choices.

## Day 1

- Python toolchain: managed by `uv` (0.11.x), pinning CPython 3.13.13 under `inference/mlx-sidecar/`. Matches build-guide guidance and CLAUDE.md stack table.
- Package manifest: `pyproject.toml` (PEP 621) rather than `requirements.txt`, because `uv` resolves and locks via `uv.lock` automatically and `pyproject.toml` is the idiomatic Python project metadata for uv-managed projects.
- Dependencies pinned: `mlx-vlm` and `torchvision`, exact resolved versions recorded in `uv.lock` and echoed in `evidence/day1/MANIFEST.md`.
- Model: `mlx-community/gemma-4-e4b-it-4bit`. Revision SHA captured in the unified registry at `inference/fingerprints/mlx-community__gemma-4-e4b-it-4bit__cc3b666c.json` (was `inference/mlx-sidecar/model-fingerprint.json` prior to the registry refactor).
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

## Day 6 (2026-05-14): registry refactor + cross-platform CI

- Fingerprints unified under `inference/fingerprints/` and embedded into the capture binary at compile time by the new `witness-fingerprints` crate (build.rs reads `index.json`). The per-sidecar `model-fingerprint.json` files and the per-sidecar `compute-fingerprint.sh` are gone; sourcing fingerprints from outside the registry is no longer possible.
- Seal command rewritten: `seal_bundle_cmd` queries the live sidecar's `/v1/models` and resolves the matching registry entry. Removes the previous compile-time path bug (would have broken in any shipped binary) and the silent "wrong fingerprint on Linux/Windows" defect.
- `tools/seed-fingerprints` is the only supported way to add a registry entry. It fetches the HF LFS oid for a pinned `(model_id, revision)`, recomputes the local SHA-256, and refuses to write on mismatch. The MLX seed kept its existing hash (the on-disk bytes have not changed) but is now flagged `verified_by: "local-roundtrip"` until a maintainer reruns the seeder.
- `witness-test-sidecar` added: hermetic OpenAI-compatible fake server used by `crates/witness-core/tests/fake-sidecar-e2e.rs` to exercise the full capture-to-seal-to-verify path on Linux and Windows in CI. No real model required.
- `transformers-sidecar/start.py` switched to passing raw audio waveforms (16 kHz mono float32, resampled with torchaudio) to the processor under `audio=`. Replaces the prior stringified-path placeholder.
- `KeyProvider` trait added in `crates/witness-core/src/key_provider.rs`. Today only `SoftwareEd25519Provider` is wired up; the `hardware-keys` Cargo feature is reserved for the future SEP/TPM backends and `compile_error!`s if enabled.
- `gethostname` crate replaces the shell-out in the seal command; sidecar pid/log files moved from `evidence/day1/` to `target/sidecar-state/`.
