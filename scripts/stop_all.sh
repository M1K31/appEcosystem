#!/usr/bin/env bash
# Stop the ecosystem registry
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Stopping Ecosystem ==="

cd "$ROOT_DIR"
python -m cli.main stop

echo "Ecosystem registry stopped."
