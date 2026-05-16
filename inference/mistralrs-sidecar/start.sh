#!/usr/bin/env bash
# Starts the mistralrs OpenAI-compatible sidecar in the background.
#
# Trust gate (audit finding S-7):
#   The mistralrs binary on $PATH MUST hash-match an entry in PINNED.json
#   for the current target triple. Enforcement is delegated to the
#   `check-pinned-binary` tool, which is the audited authority on the gate
#   logic and is covered by its own test suite.
#
# Usage: ./start.sh
# Environment:
#   GW_SIDECAR_MODEL              default google/gemma-4-E4B-it
#   GW_SIDECAR_PORT               default 8080
#   GW_SIDECAR_HOST               default 127.0.0.1 (loopback enforced)
#   WITNESS_MISTRALRS_LOCAL_DEV   when set to 1, soft gate failures
#                                 (placeholder pin, unknown triple, hash
#                                 mismatch) downgrade to a loud warning. The
#                                 release-gate live e2e MUST NOT set this.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${WITNESS_REPO_ROOT_OVERRIDE:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
PINNED_PATH="${WITNESS_PINNED_PATH_OVERRIDE:-$SCRIPT_DIR/PINNED.json}"
MODEL="${GW_SIDECAR_MODEL:-google/gemma-4-E4B-it}"
PORT="${GW_SIDECAR_PORT:-8080}"
HOST="${GW_SIDECAR_HOST:-127.0.0.1}"
LOCAL_DEV="${WITNESS_MISTRALRS_LOCAL_DEV:-0}"

case "$HOST" in
  127.0.0.1|::1|localhost) ;;
  *)
    echo "refusing to bind mistralrs sidecar to non-loopback host \"$HOST\". the capture app trusts whatever returns on /v1/chat/completions as the model output, so a sidecar reachable from the network is a forgery vector. set GW_SIDECAR_HOST to 127.0.0.1, ::1, or localhost." >&2
    exit 64
    ;;
esac

if ! command -v mistralrs >/dev/null 2>&1; then
  echo "mistralrs not found on PATH. install via the pinned cargo install command in inference/mistralrs-sidecar/README.md." >&2
  exit 65
fi

if [ ! -f "$PINNED_PATH" ]; then
  echo "missing $PINNED_PATH. the mistralrs sidecar refuses to launch without a hash-pin manifest; restore it from git and retry." >&2
  exit 67
fi

# Resolve check-pinned-binary. Prefer the workspace target/release build, then
# target/debug, then any copy on PATH. Build it if it's missing entirely so
# the gate is never skipped silently because the tool wasn't compiled.
resolve_check_tool() {
  for candidate in \
      "$REPO_ROOT/target/release/check-pinned-binary" \
      "$REPO_ROOT/target/debug/check-pinned-binary"; do
    if [ -x "$candidate" ]; then
      echo "$candidate"
      return
    fi
  done
  if command -v check-pinned-binary >/dev/null 2>&1; then
    command -v check-pinned-binary
    return
  fi
  return 1
}

CHECK_TOOL="$(resolve_check_tool || true)"
if [ -z "$CHECK_TOOL" ]; then
  echo "check-pinned-binary not built. run \`cargo build --release -p check-pinned-binary\` and retry. this tool enforces the SHA-256 pin on the mistralrs binary; the sidecar will not launch without it." >&2
  exit 68
fi

MISTRALRS_BIN="$(command -v mistralrs)"

CHECK_ARGS=(--pinned "$PINNED_PATH" --binary "$MISTRALRS_BIN")
if [ "$LOCAL_DEV" = "1" ]; then
  CHECK_ARGS+=(--allow-local-dev)
fi

if ! "$CHECK_TOOL" "${CHECK_ARGS[@]}"; then
  echo "check-pinned-binary refused launch. see message above. fix the pin or, for local development only, export WITNESS_MISTRALRS_LOCAL_DEV=1." >&2
  exit 66
fi

STATE_DIR="$REPO_ROOT/target/sidecar-state"
mkdir -p "$STATE_DIR"
PID_FILE="$STATE_DIR/mistralrs-sidecar.pid"
LOG_FILE="$STATE_DIR/mistralrs-sidecar.log"

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
