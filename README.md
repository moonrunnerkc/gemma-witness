# Gemma.Witness

Offline, multimodal, tamper-evident evidence capture for civic accountability. Tauri 2.x desktop app, static HTML verifier, and a Rust core library. Local inference via Gemma 4 E4B through mlx-vlm on Apple Silicon.

See `CLAUDE.md` and `.github/copilot-instructions.md` for engineering standards. See `build-guide.md` for the eight-day plan.

## Day 1 status

Inference sidecar bring-up. See `evidence/day1/MANIFEST.md` for gate-by-gate evidence.

## Quick start (Day 1 only)

```bash
# Bring up the mlx-vlm sidecar (auto-downloads model on first run)
./inference/mlx-sidecar/start.sh

# Transcribe an audio file against the running sidecar
uv run --project inference/mlx-sidecar \
  python inference/mlx-sidecar/cli/transcribe.py tests/fixtures/day1-sample.wav

# Stop the sidecar
./inference/mlx-sidecar/stop.sh
```
