#!/usr/bin/env bash
# Ecosystem acceptance smoke test — single-host, subset, and networked-split
# guarantees. Runs the real registry app in an isolated temp environment (no
# real config/data/secret touched, no ports, no external services).
#
# Exits non-zero on any failed check. Safe to run in CI and on macOS or Linux.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Prefer the repo venv; fall back to whatever python3 is on PATH.
if [ -x "$REPO/.venv/bin/python" ]; then
  PY="$REPO/.venv/bin/python"
elif [ -x "$HOME/.local/share/ecosystem/venv/bin/python" ]; then
  PY="$HOME/.local/share/ecosystem/venv/bin/python"
else
  PY="$(command -v python3 || true)"
fi
[ -n "$PY" ] || { echo "ERROR: no python interpreter found"; exit 1; }

exec "$PY" "$REPO/scripts/smoke_ecosystem.py" "$@"
