#!/usr/bin/env bash
# Remove the ecosystem registry service:
#   macOS -> launchd (via `cli uninstall`)
#   Linux -> systemd (via scripts/uninstall_systemd.sh, needs sudo)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
OS="$(uname -s)"

echo "=== Uninstalling Ecosystem Service ($OS) ==="

cd "$ROOT_DIR"

case "$OS" in
  Darwin)
    if [ -f "$ROOT_DIR/.venv/bin/python" ]; then
        "$ROOT_DIR/.venv/bin/python" -m cli.main uninstall
    else
        python -m cli.main uninstall
    fi
    ;;
  Linux)
    if [ -x "$SCRIPT_DIR/uninstall_systemd.sh" ]; then
        sudo "$SCRIPT_DIR/uninstall_systemd.sh" || \
            echo "systemd uninstall skipped/failed — run 'sudo scripts/uninstall_systemd.sh' manually."
    fi
    ;;
  *)
    echo "Unknown OS '$OS' — nothing to remove."
    ;;
esac

# Optionally remove virtual environment
read -rp "Remove virtual environment (.venv)? [y/N] " answer
if [[ "$answer" =~ ^[Yy] ]]; then
    rm -rf "$ROOT_DIR/.venv"
    echo "Virtual environment removed."
fi

echo "Service removed. You can still run manually with: python -m cli.main start"
