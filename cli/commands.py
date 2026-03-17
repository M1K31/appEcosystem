"""CLI command implementations for ecosystem management."""

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import httpx
import yaml

ECOSYSTEM_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = ECOSYSTEM_DIR / "ecosystem.yaml"
PID_FILE = ECOSYSTEM_DIR / "data" / "registry.pid"
DATA_DIR = ECOSYSTEM_DIR / "data"
PLIST_NAME = "com.ecosystem.registry"
PLIST_PATH = Path.home() / "Library" / "LaunchAgents" / f"{PLIST_NAME}.plist"


def _load_config() -> dict:
    """Load ecosystem.yaml config."""
    if not CONFIG_PATH.exists():
        print(f"Error: {CONFIG_PATH} not found")
        sys.exit(1)
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# Project helpers
# ---------------------------------------------------------------------------

def _resolve_projects(config: dict) -> list[dict]:
    """Resolve project definitions from config into a list of project dicts."""
    base = Path(config.get("ecosystem", {}).get("base_path", ""))
    projects = []
    for key, proj in (config.get("projects") or {}).items():
        projects.append({
            "key": key,
            "name": proj.get("name", key),
            "abs_path": base / proj["path"],
            "host": proj.get("host", "localhost"),
            "port": proj["port"],
            "health_endpoint": proj.get("health_endpoint", "/health"),
            "start_command": proj.get("start_command", ""),
        })
    return projects


async def _check_health(host: str, port: int, endpoint: str) -> bool:
    """Check if a service is healthy by hitting its health endpoint."""
    try:
        resp = httpx.get(f"http://{host}:{port}{endpoint}", timeout=3.0)
        return resp.status_code == 200
    except Exception:
        return False


def _format_status_line(name: str, port: int, healthy: bool) -> str:
    """Format a single status line for a project."""
    status = "HEALTHY" if healthy else "DOWN"
    return f"{name:<20} port {port:<6} {status}"


def _get_pid_file(key: str) -> Path:
    """Return the PID file path for a project."""
    return DATA_DIR / f"{key}.pid"


def _get_log_file(key: str) -> Path:
    """Return the log file path for a project."""
    return DATA_DIR / f"{key}.log"


def _is_running(key: str) -> bool:
    """Check if a project process is still running."""
    pid_file = _get_pid_file(key)
    if not pid_file.exists():
        return False
    try:
        pid = int(pid_file.read_text().strip())
        os.kill(pid, 0)  # signal 0 = check existence
        return True
    except (ProcessLookupError, ValueError, OSError):
        return False


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


def cmd_start_all() -> int:
    """Start the registry and all configured projects."""
    # Start registry first
    cmd_start()

    config = _load_config()
    projects = _resolve_projects(config)
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    for proj in projects:
        key = proj["key"]
        name = proj["name"]
        cmd = proj["start_command"]
        abs_path = proj["abs_path"]

        if not cmd:
            print(f"  {name}: no start_command configured, skipping")
            continue

        if not abs_path.exists():
            print(f"  {name}: path {abs_path} not found, skipping")
            continue

        if _is_running(key):
            print(f"  {name}: already running")
            continue

        log_file = _get_log_file(key)
        with open(log_file, "a") as log_fh:
            proc = subprocess.Popen(
                cmd.split(),
                cwd=str(abs_path),
                stdout=log_fh,
                stderr=subprocess.STDOUT,
            )
        _get_pid_file(key).write_text(str(proc.pid))
        print(f"  {name}: started (PID {proc.pid})")

    return 0


def cmd_stop_all() -> int:
    """Stop all projects and then the registry."""
    config = _load_config()
    projects = _resolve_projects(config)

    for proj in reversed(projects):
        key = proj["key"]
        name = proj["name"]
        pid_file = _get_pid_file(key)

        if not pid_file.exists():
            continue

        pid = int(pid_file.read_text().strip())
        try:
            os.kill(pid, signal.SIGTERM)
            print(f"  {name}: stopped (PID {pid})")
        except ProcessLookupError:
            print(f"  {name}: already stopped (stale PID)")
        pid_file.unlink(missing_ok=True)

    # Stop registry last
    cmd_stop()
    return 0


def cmd_logs(project: str | None = None, lines: int = 50) -> int:
    """Tail log files for a project (or list available logs)."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if project is None:
        # List available log files
        log_files = sorted(DATA_DIR.glob("*.log"))
        if not log_files:
            print("No log files found.")
            return 0
        print("Available logs:")
        for lf in log_files:
            size = lf.stat().st_size
            print(f"  {lf.stem:<20} {size:>8} bytes  {lf}")
        return 0

    log_file = _get_log_file(project)
    if not log_file.exists():
        print(f"No log file found for '{project}'")
        print(f"Expected: {log_file}")
        return 1

    # Read last N lines
    try:
        all_lines = log_file.read_text().splitlines()
        tail = all_lines[-lines:]
        for line in tail:
            print(line)
    except Exception as e:
        print(f"Error reading log: {e}")
        return 1
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
