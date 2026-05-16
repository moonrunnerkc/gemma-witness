#!/usr/bin/env bash
# Integration test: start.sh must propagate the check-pinned-binary gate's
# decision before invoking `mistralrs serve`. A swapped binary that does not
# match PINNED.json must cause start.sh to exit non-zero without ever
# launching the sidecar process.
#
# Usage: ./start-sh-gate.sh
# Prerequisite: `cargo build -p check-pinned-binary` has run (or this script
# will build it). The test exercises the real start.sh in this directory
# against a scratch PINNED.json passed via WITNESS_PINNED_PATH_OVERRIDE.
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIDECAR_DIR="$(cd "$TEST_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SIDECAR_DIR/../.." && pwd)"
START_SH="$SIDECAR_DIR/start.sh"

if [ ! -x "$START_SH" ]; then
  echo "FAIL: $START_SH missing or not executable" >&2
  exit 1
fi

# Build the gate tool if it isn't on disk yet.
if [ ! -x "$REPO_ROOT/target/release/check-pinned-binary" ] \
   && [ ! -x "$REPO_ROOT/target/debug/check-pinned-binary" ]; then
  ( cd "$REPO_ROOT" && cargo build -p check-pinned-binary >/dev/null 2>&1 )
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# Shim mistralrs binary that, if invoked, writes a sentinel file. We assert
# the sentinel does NOT exist after a gated-fail run.
SHIM_PATH="$WORKDIR/bin/mistralrs"
mkdir -p "$WORKDIR/bin"
SENTINEL="$WORKDIR/mistralrs-invoked.flag"
cat >"$SHIM_PATH" <<EOF
#!/usr/bin/env bash
touch "$SENTINEL"
case "\${1:-}" in
  --version) echo "mistralrs 0.7.0"; exit 0 ;;
  serve)     sleep 600; exit 0 ;;
  *)         exit 0 ;;
esac
EOF
chmod +x "$SHIM_PATH"

SHIM_SHA="$(shasum -a 256 "$SHIM_PATH" | awk '{print $1}')"
case "$(uname -s)/$(uname -m)" in
  Darwin/arm64)     TRIPLE="aarch64-apple-darwin" ;;
  Darwin/x86_64)    TRIPLE="x86_64-apple-darwin" ;;
  Linux/x86_64)     TRIPLE="x86_64-unknown-linux-gnu" ;;
  Linux/aarch64)    TRIPLE="aarch64-unknown-linux-gnu" ;;
  *)
    echo "FAIL: unsupported test host $(uname -s)/$(uname -m)" >&2
    exit 1
    ;;
esac

PINNED_TMP="$WORKDIR/PINNED.json"
write_pinned() {
  local placeholder="$1"
  local sha="$2"
  cat <<EOF >"$PINNED_TMP"
{
  "schema_version": 1,
  "upstream_repo": "https://github.com/EricLBuehler/mistral.rs",
  "upstream_commit": "feedbeef",
  "version_string": "mistralrs 0.7.0",
  "placeholder": $placeholder,
  "binaries": [
    { "target_triple": "$TRIPLE", "sha256": "$sha" }
  ]
}
EOF
}

run_start_sh() {
  PATH="$WORKDIR/bin:$PATH" \
  GW_SIDECAR_HOST=127.0.0.1 \
  GW_SIDECAR_PORT=19191 \
  WITNESS_MISTRALRS_LOCAL_DEV=0 \
  WITNESS_PINNED_PATH_OVERRIDE="$PINNED_TMP" \
  "$START_SH" 2>&1 || true
}

# -- Case 1: hash mismatch -> the sentinel must NOT appear -----------------
rm -f "$SENTINEL"
write_pinned false "0000000000000000000000000000000000000000000000000000000000000000"
OUTPUT="$(run_start_sh)"
if [ -e "$SENTINEL" ]; then
  echo "FAIL: hash mismatch must abort BEFORE invoking mistralrs, but the shim was invoked. output: $OUTPUT" >&2
  exit 1
fi
echo "$OUTPUT" | grep -q "has SHA-256" || {
  echo "FAIL: hash mismatch output missing expected diagnostic. got: $OUTPUT" >&2
  exit 1
}
echo "PASS Case 1: hash mismatch aborts before launch"

# -- Case 2: placeholder pin -> the sentinel must NOT appear ---------------
rm -f "$SENTINEL"
write_pinned true "$SHIM_SHA"
OUTPUT="$(run_start_sh)"
if [ -e "$SENTINEL" ]; then
  echo "FAIL: placeholder PINNED.json must abort BEFORE invoking mistralrs, but the shim was invoked. output: $OUTPUT" >&2
  exit 1
fi
echo "$OUTPUT" | grep -q "placeholder=true" || {
  echo "FAIL: placeholder output missing diagnostic. got: $OUTPUT" >&2
  exit 1
}
echo "PASS Case 2: placeholder pin aborts before launch"

# -- Case 3: hash matches -> the sentinel MUST appear ----------------------
# Portable timeout: launch in a subshell, sleep briefly, then kill. macOS does
# not ship GNU coreutils' `timeout` by default, so we cannot rely on it.
rm -f "$SENTINEL"
write_pinned false "$SHIM_SHA"
(
  PATH="$WORKDIR/bin:$PATH" \
  GW_SIDECAR_HOST=127.0.0.1 \
  GW_SIDECAR_PORT=19191 \
  WITNESS_MISTRALRS_LOCAL_DEV=0 \
  WITNESS_PINNED_PATH_OVERRIDE="$PINNED_TMP" \
  "$START_SH" >/dev/null 2>&1 || true
) &
START_PID=$!
# Allow time for the gate check + the shim's `serve` invocation to fire.
for _ in 1 2 3 4 5 6; do
  if [ -e "$SENTINEL" ]; then break; fi
  sleep 1
done
kill "$START_PID" 2>/dev/null || true
wait "$START_PID" 2>/dev/null || true
PID_FILE="$REPO_ROOT/target/sidecar-state/mistralrs-sidecar.pid"
if [ -f "$PID_FILE" ]; then
  pid="$(cat "$PID_FILE")"
  kill "$pid" 2>/dev/null || true
  rm -f "$PID_FILE"
fi
if [ ! -e "$SENTINEL" ]; then
  echo "FAIL: matching hash should permit launch, but the shim was never invoked." >&2
  exit 1
fi
echo "PASS Case 3: matching hash permits launch"

echo ""
echo "All start-sh-gate tests passed."
