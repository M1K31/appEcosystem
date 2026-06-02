#!/usr/bin/env bash
# Remove ecosystem launchd service
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Uninstalling Ecosystem Service ==="

cd "$ROOT_DIR"

# Use venv python if available
if [ -f "$ROOT_DIR/.venv/bin/python" ]; then
    "$ROOT_DIR/.venv/bin/python" -m cli.main uninstall
else
    python -m cli.main uninstall
fi

# Optionally remove virtual environment
read -rp "Remove virtual environment (.venv)? [y/N] " answer
if [[ "$answer" =~ ^[Yy] ]]; then
    rm -rf "$ROOT_DIR/.venv"
    echo "Virtual environment removed."
fi

echo "Service removed. You can still run manually with: python -m cli.main start"
