#!/usr/bin/env bash
# Install the appEcosystem registry to a STABLE INTERNAL-DISK path.
#   macOS -> launchd user agent (com.ecosystem.registry)
#   Linux -> systemd system service (ecosystem-registry.service, needs sudo)
#
# Why internal disk: a launchd/systemd service whose venv lives on a removable/
# external volume fails (macOS TCC/exec restrictions; SIGBUS if the volume drops
# mid-run). The runtime lives on the internal disk; the source/config stay in the
# repo. The shared secret is file-backed (~/.config/ecosystem/secret.env), so no
# launchctl setenv / per-plist secret is needed.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="$HOME/.local/share/ecosystem"
VENV="$PREFIX/venv"
DATA="$PREFIX/data"
PY="${PYTHON_BIN:-python3.12}"
OS="$(uname -s)"
PORT="${ECOSYSTEM_REGISTRY_PORT:-8500}"
MODE="${ECOSYSTEM_MODE:-local}"
# Bind host follows the deployment mode unless explicitly overridden: loopback
# in local mode, all interfaces in lan mode so other devices can reach the
# control plane (firewall it to the trusted network).
if [ -n "${ECOSYSTEM_REGISTRY_HOST:-}" ]; then
  BIND="$ECOSYSTEM_REGISTRY_HOST"
elif [ "$MODE" = "lan" ]; then
  BIND="0.0.0.0"
else
  BIND="127.0.0.1"
fi
CONFIG="${ECOSYSTEM_CONFIG:-$REPO/ecosystem.yaml}"
LABEL="com.ecosystem.registry"

command -v "$PY" >/dev/null 2>&1 || { echo "ERROR: $PY not found on PATH"; exit 1; }

echo "==> Installing ecosystem registry runtime to $PREFIX ($OS)"
mkdir -p "$PREFIX" "$DATA"
[ -d "$VENV" ] || "$PY" -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip wheel >/dev/null
# Non-editable so the importable code lives on the internal disk, not the repo volume.
"$VENV/bin/pip" install "$REPO" "$REPO/auth/python" \
                        "$REPO/packages/ecosystem-ai" "$REPO/packages/ecosystem-client"

# Provision the shared secret (file-backed; reused if it already exists).
"$VENV/bin/python" -c "from ecosystem_auth.tokens import ensure_ecosystem_secret; ensure_ecosystem_secret()" \
    && echo "==> Shared secret ready (~/.config/ecosystem/secret.env)"

case "$OS" in
  Darwin)
    PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
    LOGDIR="$HOME/Library/Logs/Ecosystem"; mkdir -p "$LOGDIR" "$HOME/Library/LaunchAgents"
    cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array>
    <string>$VENV/bin/python</string>
    <string>-m</string><string>uvicorn</string><string>registry.app:app</string>
    <string>--host</string><string>$BIND</string>
    <string>--port</string><string>$PORT</string>
  </array>
  <key>WorkingDirectory</key><string>$PREFIX</string>
  <key>EnvironmentVariables</key><dict>
    <key>ECOSYSTEM_CONFIG</key><string>$CONFIG</string>
    <key>ECOSYSTEM_MODE</key><string>$MODE</string>
    <key>ECOSYSTEM_REGISTRY_FILE</key><string>$DATA/registry.json</string>
    <key>ECOSYSTEM_AI_PROFILE_FILE</key><string>$DATA/ai_profile.json</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$LOGDIR/registry.stdout.log</string>
  <key>StandardErrorPath</key><string>$LOGDIR/registry.stderr.log</string>
</dict></plist>
PLIST_EOF
    launchctl unload "$PLIST" 2>/dev/null || true
    launchctl load "$PLIST"
    echo "==> Registry installed and loaded (launchd: $LABEL, $BIND:$PORT)"
    echo "    Logs: $LOGDIR/registry.{stdout,stderr}.log"
    ;;
  Linux)
    if [ "$EUID" -ne 0 ]; then echo "Linux install needs sudo: sudo $0"; exit 1; fi
    USER_NAME="${SUDO_USER:-$USER}"
    UNIT="/etc/systemd/system/ecosystem-registry.service"
    cat > "$UNIT" <<UNIT_EOF
[Unit]
Description=appEcosystem Service Registry
After=network.target
[Service]
Type=simple
User=$USER_NAME
WorkingDirectory=$PREFIX
Environment=ECOSYSTEM_CONFIG=$CONFIG
Environment=ECOSYSTEM_MODE=$MODE
Environment=ECOSYSTEM_REGISTRY_FILE=$DATA/registry.json
Environment=ECOSYSTEM_AI_PROFILE_FILE=$DATA/ai_profile.json
ExecStart=$VENV/bin/python -m uvicorn registry.app:app --host $BIND --port $PORT
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT_EOF
    systemctl daemon-reload
    systemctl enable ecosystem-registry.service
    echo "==> Registry installed (systemd). Start: sudo systemctl start ecosystem-registry"
    ;;
  *)
    echo "Unsupported OS: $OS"; exit 1 ;;
esac
# The cyber-harness daemon (port 8088) is registered in ecosystem.yaml as the
# preferred security-analysis backend. Prepare its runtime so it is available
# when wanted, but do NOT start it — launchd owns that service and enabling it
# stays an explicit, separate step. Never fatal: the registry runs without it.
HARNESS="${CYBER_HARNESS_PATH:-${ECOSYSTEM_BASE_PATH:-$REPO/..}/CybersecurityTeam/cyber-claude-agents}"
if [ -n "${ECOSYSTEM_SKIP_HARNESS:-}" ]; then
    echo "==> ECOSYSTEM_SKIP_HARNESS=1 — skipping cyber-harness setup."
elif [ -x "$HARNESS/scripts/install-local.sh" ]; then
    echo "==> Preparing cyber-harness runtime (opt-in; enable with its --plist)"
    ECOSYSTEM_BASE_PATH="${ECOSYSTEM_BASE_PATH:-$REPO/..}" \
        "$HARNESS/scripts/install-local.sh" >/dev/null 2>&1 \
        && echo "    cyber-harness runtime ready (not started)" \
        || echo "    NOTE: cyber-harness setup skipped (non-fatal)."
else
    echo "==> cyber-harness not present at $HARNESS — skipping (optional component)."
fi

echo "==> Done."
