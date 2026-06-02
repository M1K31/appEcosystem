#!/usr/bin/env bash
# uninstall_systemd.sh — Remove the Linux systemd service.
# Run with sudo permissions.
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run this script with sudo privileges:"
    echo "sudo $0"
    exit 1
fi

echo "=== Uninstalling Ecosystem Registry systemd Service ==="

SERVICE_FILE="/etc/systemd/system/ecosystem-registry.service"

if [ -f "$SERVICE_FILE" ]; then
    echo "Stopping ecosystem-registry service..."
    systemctl stop ecosystem-registry.service || true

    echo "Disabling ecosystem-registry service..."
    systemctl disable ecosystem-registry.service || true

    echo "Removing $SERVICE_FILE..."
    rm -f "$SERVICE_FILE"

    echo "Reloading systemd daemon..."
    systemctl daemon-reload

    echo "=== Service successfully uninstalled ==="
else
    echo "No systemd service unit found at $SERVICE_FILE"
fi
EOF
