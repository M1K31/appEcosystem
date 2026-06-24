#!/usr/bin/env bash
# Install the ecosystem registry as a service:
#   macOS -> launchd (via `cli install`)
#   Linux -> systemd (via scripts/install_systemd.sh, needs sudo)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
OS="$(uname -s)"

echo "=== Installing Ecosystem Service ($OS) ==="

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

# Install the shared ecosystem packages (path install until published).
# Apps guard these imports, so this activates the shared AI layer + sync.
pip install -e "$ROOT_DIR/packages/ecosystem-ai"
pip install -e "$ROOT_DIR/packages/ecosystem-client"

# Install JS dependencies
if command -v npm &>/dev/null; then
    npm install --workspaces 2>/dev/null || true
fi

# Install the registry as a service via the internal-disk installer (runs the
# runtime off the internal disk, not the source volume; provisions the shared
# secret). It detects the OS (launchd on macOS, systemd on Linux).
if [ -x "$SCRIPT_DIR/install-local.sh" ]; then
    if [ "$OS" = "Linux" ] && [ "$EUID" -ne 0 ]; then
        sudo "$SCRIPT_DIR/install-local.sh" || \
            echo "Service install skipped/failed — run 'sudo scripts/install-local.sh' manually."
    else
        "$SCRIPT_DIR/install-local.sh"
    fi
else
    echo "scripts/install-local.sh missing — start manually with 'python -m cli.main start'."
fi

echo ""
echo "Installation complete."
echo "Virtual environment: $VENV_DIR  (activate: source .venv/bin/activate)"
echo "Check status with: python -m cli.main status"
