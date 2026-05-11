#!/usr/bin/env bash
# Day 1 smoke test: runs the transcribe CLI against the fixture WAV and asserts
# the reference phrase appears in the transcript (case-insensitive substring).
#
# Preconditions:
#   - sidecar running on http://127.0.0.1:8080
#   - tests/fixtures/day1-sample.wav exists
#
# Exit code: 0 on PASS, non-zero on FAIL.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIXTURE="$REPO_ROOT/tests/fixtures/day1-sample.wav"
CLI="$REPO_ROOT/inference/mlx-sidecar/cli/transcribe.py"

export PATH="$HOME/.local/bin:$PATH"

TRANSCRIPT="$(uv run --project "$REPO_ROOT/inference/mlx-sidecar" python "$CLI" "$FIXTURE")"
echo "TRANSCRIPT: $TRANSCRIPT"

needle_lower="witness arrived at the corner of main street"
transcript_lower="$(printf '%s' "$TRANSCRIPT" | tr '[:upper:]' '[:lower:]' | tr -s '[:space:]' ' ')"

if [[ "$transcript_lower" != *"$needle_lower"* ]]; then
  echo "FAIL: reference phrase not found in transcript." >&2
  echo "expected substring: $needle_lower" >&2
  exit 1
fi

echo "PASS: reference phrase found in transcript."
