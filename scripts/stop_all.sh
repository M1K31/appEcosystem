#!/usr/bin/env bash
# Stop the ecosystem registry
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Stopping Ecosystem ==="

cd "$ROOT_DIR"
if [ -f "$ROOT_DIR/.venv/bin/activate" ]; then
    source "$ROOT_DIR/.venv/bin/activate"
fi
python -m cli.main stop

echo "Ecosystem registry stopped."
