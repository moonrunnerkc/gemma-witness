#!/usr/bin/env bash
# Starts the mlx-vlm OpenAI-compatible sidecar in the background.
# Writes the PID to target/sidecar-state/mlx-sidecar.pid and logs to
# target/sidecar-state/mlx-sidecar.log.
# Waits until the server is reachable on the configured port before returning.
#
# Usage: ./start.sh
# Environment:
#   GW_SIDECAR_MODEL  default mlx-community/gemma-4-e4b-it-4bit
#   GW_SIDECAR_PORT   default 8080
#   GW_SIDECAR_HOST   default 127.0.0.1
#   GW_SIDECAR_FOREGROUND  when 1, run the server in the foreground
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MODEL="${GW_SIDECAR_MODEL:-mlx-community/gemma-4-e4b-it-4bit}"
PORT="${GW_SIDECAR_PORT:-8080}"
HOST="${GW_SIDECAR_HOST:-127.0.0.1}"
FOREGROUND="${GW_SIDECAR_FOREGROUND:-0}"

case "$HOST" in
  127.0.0.1|::1|localhost) ;;
  *)
    echo "refusing to bind sidecar to non-loopback host \"$HOST\". the capture app trusts whatever returns on /v1/chat/completions as the model output, so a sidecar reachable from the network is a forgery vector. set GW_SIDECAR_HOST to 127.0.0.1, ::1, or localhost." >&2
    exit 64
    ;;
esac

STATE_DIR="$REPO_ROOT/target/sidecar-state"
mkdir -p "$STATE_DIR"
PID_FILE="$STATE_DIR/mlx-sidecar.pid"
LOG_FILE="$STATE_DIR/mlx-sidecar.log"

if [ -f "$PID_FILE" ]; then
  TRACKED_PID="$(cat "$PID_FILE")"
  if kill -0 "$TRACKED_PID" 2>/dev/null; then
    echo "sidecar already running with pid $TRACKED_PID. run stop.sh first." >&2
    exit 1
  fi
  echo "cleaning up stale sidecar pid file for pid $TRACKED_PID."
  rm -f "$PID_FILE"
fi

export PATH="$HOME/.local/bin:$PATH"
cd "$SCRIPT_DIR"
uv sync --frozen

PYTHON="$SCRIPT_DIR/.venv/bin/python"
if [ ! -x "$PYTHON" ]; then
  echo "expected uv-managed python at $PYTHON after uv sync, but it is missing." >&2
  exit 65
fi

if [ "$FOREGROUND" = "1" ]; then
  echo "starting mlx-vlm sidecar in foreground model=$MODEL host=$HOST port=$PORT"
  export PYTHONUNBUFFERED=1
  exec "$PYTHON" -m mlx_vlm server \
    --model "$MODEL" \
    --host "$HOST" \
    --port "$PORT"
fi

: > "$LOG_FILE"
PYTHONUNBUFFERED=1 nohup "$PYTHON" -m mlx_vlm server \
  --model "$MODEL" \
  --host "$HOST" \
  --port "$PORT" \
  >> "$LOG_FILE" 2>&1 &
SIDE_PID=$!
echo "$SIDE_PID" > "$PID_FILE"
echo "started mlx-vlm sidecar pid=$SIDE_PID model=$MODEL host=$HOST port=$PORT log=$LOG_FILE"

DEADLINE=$(( $(date +%s) + 240 ))
while :; do
  if ! kill -0 "$SIDE_PID" 2>/dev/null; then
    echo "sidecar process died during startup. inspect $LOG_FILE for cause." >&2
    exit 2
  fi
  if curl -sf -o /dev/null "http://${HOST}:${PORT}/v1/models"; then
    echo "sidecar ready on http://${HOST}:${PORT}"
    exit 0
  fi
  if [ "$(date +%s)" -gt "$DEADLINE" ]; then
    echo "timed out waiting for sidecar on port $PORT after 240s. inspect $LOG_FILE." >&2
    exit 3
  fi
  sleep 2
done
