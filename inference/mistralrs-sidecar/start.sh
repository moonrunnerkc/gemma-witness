#!/usr/bin/env bash
# Starts the mistralrs OpenAI-compatible sidecar in the background.
# Writes the PID to evidence/day1/mistralrs-sidecar.pid and logs to evidence/day1/mistralrs-sidecar.log.
# Waits until the server is reachable on the configured port before returning.
#
# Usage: ./start.sh
# Environment:
#   GW_SIDECAR_MODEL  default google/gemma-4-E4B-it
#   GW_SIDECAR_PORT   default 8080
#   GW_SIDECAR_HOST   default 127.0.0.1
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MODEL="${GW_SIDECAR_MODEL:-google/gemma-4-E4B-it}"
PORT="${GW_SIDECAR_PORT:-8080}"
HOST="${GW_SIDECAR_HOST:-127.0.0.1}"

EVIDENCE_DIR="$REPO_ROOT/evidence/day1"
mkdir -p "$EVIDENCE_DIR"
PID_FILE="$EVIDENCE_DIR/mistralrs-sidecar.pid"
LOG_FILE="$EVIDENCE_DIR/mistralrs-sidecar.log"

if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "mistralrs sidecar already running with pid $(cat "$PID_FILE"). run stop.sh first." >&2
  exit 1
fi

export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

: > "$LOG_FILE"
nohup mistralrs serve \
  -m "$MODEL" \
  --isq 4 \
  --port "$PORT" \
  --host "$HOST" \
  >> "$LOG_FILE" 2>&1 &
SIDE_PID=$!
echo "$SIDE_PID" > "$PID_FILE"
echo "started mistralrs sidecar pid=$SIDE_PID model=$MODEL host=$HOST port=$PORT log=$LOG_FILE"

DEADLINE=$(( $(date +%s) + 240 ))
while :; do
  if ! kill -0 "$SIDE_PID" 2>/dev/null; then
    echo "mistralrs sidecar process died during startup. inspect $LOG_FILE for cause." >&2
    exit 2
  fi
  if curl -sf -o /dev/null "http://${HOST}:${PORT}/v1/models"; then
    echo "mistralrs sidecar ready on http://${HOST}:${PORT}"
    exit 0
  fi
  if [ "$(date +%s)" -gt "$DEADLINE" ]; then
    echo "timed out waiting for mistralrs sidecar on port $PORT after 240s. inspect $LOG_FILE." >&2
    exit 3
  fi
  sleep 2
done
