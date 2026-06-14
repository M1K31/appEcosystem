#!/usr/bin/env bash
# install_systemd.sh — Install the ecosystem registry as a Linux systemd service.
# Run with sudo permissions on Linux.
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run this script with sudo privileges:"
    echo "sudo $0"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
USER_NAME="${SUDO_USER:-$USER}"
USER_HOME=$(getent passwd "$USER_NAME" | cut -d: -f6)

echo "=== Installing Ecosystem Registry as systemd Service ==="
echo "User: $USER_NAME"
echo "Working Directory: $ROOT_DIR"

# 1. Verify virtual environment python
PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
if [ ! -f "$PYTHON_BIN" ]; then
    PYTHON_BIN=$(command -v python3)
    echo "Warning: Virtual environment python not found. Falling back to system python: $PYTHON_BIN"
fi

# 2. Write systemd Service Unit file
SERVICE_FILE="/etc/systemd/system/ecosystem-registry.service"
echo "Generating $SERVICE_FILE..."

cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=appEcosystem Central Service Registry & Event Bus
After=network.target

[Service]
Type=simple
User=$USER_NAME
WorkingDirectory=$ROOT_DIR
Environment=ECOSYSTEM_REGISTRY_FILE=data/registry.json
ExecStart=$PYTHON_BIN scripts/process_manager.py --cmd "$PYTHON_BIN -m uvicorn registry.app:app --host 0.0.0.0 --port 8500" --log data/registry.log
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# 3. Reload systemd, enable, and start service
echo "Reloading systemd daemon..."
systemctl daemon-reload

echo "Enabling ecosystem-registry service..."
systemctl enable ecosystem-registry.service

echo "Starting ecosystem-registry service..."
systemctl start ecosystem-registry.service

echo ""
echo "=== systemd Service Installed and Started Successfully ==="
echo "Check status with: sudo systemctl status ecosystem-registry"
echo "View service logs with: journalctl -u ecosystem-registry -f"
