#!/usr/bin/env bash
# Start the ecosystem registry and optionally all project services
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Starting Ecosystem ==="

# Activate venv if available
cd "$ROOT_DIR"
if [ -f "$ROOT_DIR/.venv/bin/activate" ]; then
    source "$ROOT_DIR/.venv/bin/activate"
fi

# Start registry
python -m cli.main start

echo ""
echo "Registry is running. Individual projects can be started from their own directories."
echo "Use 'python -m cli.main status' to check all service health."
