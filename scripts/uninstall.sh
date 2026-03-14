#!/usr/bin/env bash
# Remove ecosystem launchd service
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Uninstalling Ecosystem Service ==="

cd "$ROOT_DIR"
python -m cli.main uninstall

echo "Service removed. You can still run manually with: python -m cli.main start"
