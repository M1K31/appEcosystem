#!/usr/bin/env bash
# Start the ecosystem registry and optionally all project services
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Starting Ecosystem ==="

# Start registry
cd "$ROOT_DIR"
python -m cli.main start

echo ""
echo "Registry is running. Individual projects can be started from their own directories."
echo "Use 'python -m cli.main status' to check all service health."
