"""CLI command implementations for start, stop, status, install, uninstall."""

import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import httpx
import yaml

ECOSYSTEM_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = ECOSYSTEM_DIR / "ecosystem.yaml"
PID_FILE = ECOSYSTEM_DIR / "data" / "registry.pid"
PLIST_NAME = "com.ecosystem.registry"
PLIST_PATH = Path.home() / "Library" / "LaunchAgents" / f"{PLIST_NAME}.plist"


def _load_config() -> dict:
    """Load ecosystem.yaml config."""
    if not CONFIG_PATH.exists():
        print(f"Error: {CONFIG_PATH} not found")
        sys.exit(1)
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


def cmd_start() -> int:
    """Start the ecosystem registry."""
    config = _load_config()
    port = config.get("registry", {}).get("port", 8500)

    print(f"Starting ecosystem registry on port {port}...")

    # Ensure data dir exists
    (ECOSYSTEM_DIR / "data").mkdir(exist_ok=True)

    proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn",
            "registry.app:app",
            "--host", "0.0.0.0",
            "--port", str(port),
        ],
        cwd=str(ECOSYSTEM_DIR),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(proc.pid))
    print(f"Registry started (PID {proc.pid})")
    return 0


def cmd_stop() -> int:
    """Stop the ecosystem registry."""
    if not PID_FILE.exists():
        print("Registry is not running (no PID file)")
        return 1

    pid = int(PID_FILE.read_text().strip())
    try:
        os.kill(pid, signal.SIGTERM)
        print(f"Stopped registry (PID {pid})")
        PID_FILE.unlink()
    except ProcessLookupError:
        print(f"Process {pid} not found - cleaning up stale PID file")
        PID_FILE.unlink()
    return 0


def cmd_status() -> int:
    """Show health status of all ecosystem services."""
    config = _load_config()
    port = config.get("registry", {}).get("port", 8500)
    registry_url = f"http://localhost:{port}"

    # Check registry itself
    try:
        resp = httpx.get(f"{registry_url}/health", timeout=3.0)
        print(f"{'Registry':<20} port {port:<6} {'HEALTHY' if resp.status_code == 200 else 'UNHEALTHY'}")
    except Exception:
        print(f"{'Registry':<20} port {port:<6} DOWN")
        print("\nRegistry is not running. Start it with: ecosystem start")
        # Fall back to config-based status
        print("\nConfigured projects:")
        for key, proj in (config.get("projects") or {}).items():
            print(f"  {proj['name']:<20} port {proj['port']:<6} (not checked)")
        return 1

    # Check registered services
    try:
        resp = httpx.get(f"{registry_url}/services", timeout=3.0)
        services = resp.json()
    except Exception:
        print("Could not fetch services from registry")
        return 1

    if not services:
        print("\nNo services registered.")
        return 0

    print(f"\n{'Service':<20} {'Port':<8} {'Status':<12} {'Last Check'}")
    print("-" * 60)
    for svc in services:
        name = svc.get("name", "?")
        port = svc.get("port", "?")
        status = svc.get("status", "unknown").upper()
        last_check = svc.get("last_health_check")
        check_str = "never" if not last_check else f"{last_check:.0f}"
        print(f"{name:<20} {str(port):<8} {status:<12} {check_str}")

    return 0


def cmd_install() -> int:
    """Install ecosystem registry as a macOS launchd service."""
    config = _load_config()
    port = config.get("registry", {}).get("port", 8500)
    python = sys.executable
    ecosystem_dir = str(ECOSYSTEM_DIR)

    plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{PLIST_NAME}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python}</string>
        <string>-m</string>
        <string>uvicorn</string>
        <string>registry.app:app</string>
        <string>--host</string>
        <string>0.0.0.0</string>
        <string>--port</string>
        <string>{port}</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{ecosystem_dir}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{ecosystem_dir}/data/registry.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>{ecosystem_dir}/data/registry.stderr.log</string>
</dict>
</plist>"""

    PLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    PLIST_PATH.write_text(plist_content)
    subprocess.run(["launchctl", "load", str(PLIST_PATH)])
    print(f"Installed and loaded {PLIST_NAME}")
    print(f"Plist: {PLIST_PATH}")
    return 0


def cmd_uninstall() -> int:
    """Remove ecosystem launchd service."""
    if PLIST_PATH.exists():
        subprocess.run(["launchctl", "unload", str(PLIST_PATH)])
        PLIST_PATH.unlink()
        print(f"Unloaded and removed {PLIST_NAME}")
    else:
        print(f"No plist found at {PLIST_PATH}")
    return 0
