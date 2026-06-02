#!/usr/bin/env bash
# Install ecosystem as a macOS launchd service
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Installing Ecosystem Service ==="

# Create data directory
mkdir -p "$ROOT_DIR/data"

# Create or reuse virtual environment
cd "$ROOT_DIR"
VENV_DIR="$ROOT_DIR/.venv"

if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment at .venv/..."
    python3 -m venv "$VENV_DIR"
fi

# Activate venv and install
source "$VENV_DIR/bin/activate"
pip install --upgrade pip -q

# Install Python dependencies
pip install -e ".[dev]" 2>/dev/null || pip install -e .

# Install JS dependencies
if command -v npm &>/dev/null; then
    npm install --workspaces 2>/dev/null || true
fi

# Install launchd service
python -m cli.main install

echo ""
echo "Installation complete. The registry will start automatically on login."
echo "Virtual environment: $VENV_DIR"
echo "Activate with: source .venv/bin/activate"
echo "Check status with: python -m cli.main status"
