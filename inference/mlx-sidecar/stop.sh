#!/usr/bin/env bash
# Stops the mlx-vlm sidecar started by start.sh.
# Reads the PID from evidence/day1/sidecar.pid and signals the process.
#
# Usage: ./stop.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PID_FILE="$REPO_ROOT/evidence/day1/sidecar.pid"

if [ ! -f "$PID_FILE" ]; then
  echo "no pid file at $PID_FILE. sidecar is not tracked as running." >&2
  exit 0
fi

PID="$(cat "$PID_FILE")"
if ! kill -0 "$PID" 2>/dev/null; then
  echo "sidecar pid $PID is not alive. cleaning up stale pid file."
  rm -f "$PID_FILE"
  exit 0
fi

kill "$PID"
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if ! kill -0 "$PID" 2>/dev/null; then
    rm -f "$PID_FILE"
    echo "sidecar pid $PID stopped."
    exit 0
  fi
  sleep 1
done

echo "sidecar pid $PID did not exit after SIGTERM. sending SIGKILL." >&2
kill -9 "$PID" 2>/dev/null || true
rm -f "$PID_FILE"
