#!/usr/bin/env bash
# Install ecosystem as a macOS launchd service
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Installing Ecosystem Service ==="

# Create data directory
mkdir -p "$ROOT_DIR/data"

# Install Python dependencies
cd "$ROOT_DIR"
pip install -e ".[dev]" 2>/dev/null || pip install -e .

# Install JS dependencies
if command -v npm &>/dev/null; then
    npm install --workspaces 2>/dev/null || true
fi

# Install launchd service
python -m cli.main install

echo ""
echo "Installation complete. The registry will start automatically on login."
echo "Check status with: python -m cli.main status"
