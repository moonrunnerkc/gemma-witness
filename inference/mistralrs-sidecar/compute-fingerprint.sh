#!/usr/bin/env bash
# Computes the SHA-256 fingerprint of the downloaded Gemma 4 E4B model.safetensors
# and updates model-fingerprint.json with the result.
#
# Usage: ./compute-fingerprint.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL_ID="google/gemma-4-E4B-it"
REPO_NAME="models--google--gemma-4-E4B-it"

HF_CACHE="$HOME/.cache/huggingface/hub"
if command -v python3 >/dev/null 2>&1; then
  PY_CACHE="$(python3 -c 'from huggingface_hub import constants; print(constants.HF_HUB_CACHE)' 2>/dev/null || true)"
  if [ -n "${PY_CACHE:-}" ]; then
    HF_CACHE="$PY_CACHE"
  fi
fi

SNAPSHOT_DIR="$HF_CACHE/$REPO_NAME/snapshots"
if [ ! -d "$SNAPSHOT_DIR" ]; then
  echo "model cache not found at $SNAPSHOT_DIR. download the model first, e.g.:" >&2
  echo "  huggingface-cli download $MODEL_ID" >&2
  exit 1
fi

LATEST_SNAPSHOT="$(ls -t "$SNAPSHOT_DIR" | head -n 1)"
MODEL_FILE="$SNAPSHOT_DIR/$LATEST_SNAPSHOT/model.safetensors"

if [ ! -f "$MODEL_FILE" ]; then
  echo "model.safetensors not found in snapshot $LATEST_SNAPSHOT. expected path:" >&2
  echo "  $MODEL_FILE" >&2
  exit 2
fi

echo "hashing $MODEL_FILE ..."

if command -v sha256sum >/dev/null 2>&1; then
  HASH="$(sha256sum "$MODEL_FILE" | cut -d' ' -f1)"
elif command -v shasum >/dev/null 2>&1; then
  HASH="$(shasum -a 256 "$MODEL_FILE" | cut -d' ' -f1)"
else
  echo "neither sha256sum nor shasum found. install one of them and try again." >&2
  exit 3
fi

SIZE_RAW="$(stat -f%z "$MODEL_FILE" 2>/dev/null || stat -c%s "$MODEL_FILE" 2>/dev/null || true)"
if [ -n "$SIZE_RAW" ]; then
  SIZE="$SIZE_RAW"
else
  SIZE="null"
fi

python3 - "$HASH" "$SIZE" "$SCRIPT_DIR/model-fingerprint.json" <<'PY'
import json
import sys
from datetime import datetime, timezone

hash_val, size_val, path = sys.argv[1], sys.argv[2], sys.argv[3]
size_out = int(size_val) if size_val.isdigit() else None

with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

for entry in data.get("files", []):
    if entry.get("path") == "model.safetensors":
        entry["sha256"] = hash_val
        entry["bytes"] = size_out
        break
else:
    data.setdefault("files", []).append(
        {"path": "model.safetensors", "sha256": hash_val, "bytes": size_out}
    )

data["captured_at_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")

print(f"updated {path} with sha256={hash_val} bytes={size_out}")
PY
