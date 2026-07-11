"""CLI command implementations for ecosystem management."""

import json
import os
import shlex
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
    """Resolve project definitions from config into a list of project dicts.

    The base path is taken from ECOSYSTEM_BASE_PATH when set, otherwise from
    ecosystem.yaml. Keeping it overridable avoids hardcoding developer-specific
    absolute paths in the committed config.
    """
    base_str = (
        os.environ.get("ECOSYSTEM_BASE_PATH")
        or config.get("ecosystem", {}).get("base_path", "")
    )
    # Default to the repo's parent directory (sibling project layout).
    base = Path(base_str) if base_str else ECOSYSTEM_DIR.parent
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


def _pid_alive(pid: int) -> bool:
    """Return True if a process with the given PID currently exists."""
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, OSError):
        return False


def _terminate_pid(pid: int, label: str, grace: float = 5.0) -> str:
    """Gracefully stop a process, escalating to SIGKILL if it does not exit.

    Sends SIGTERM, polls for up to ``grace`` seconds, then sends SIGKILL.
    Returns a human-readable outcome string.
    """
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return f"{label}: already stopped (stale PID)"

    waited = 0.0
    interval = 0.2
    while waited < grace:
        if not _pid_alive(pid):
            return f"{label}: stopped (PID {pid})"
        time.sleep(interval)
        waited += interval

    # Grace period exceeded — force kill to avoid orphaned processes.
    try:
        os.kill(pid, signal.SIGKILL)
        return f"{label}: force-killed after {grace:.0f}s (PID {pid})"
    except ProcessLookupError:
        return f"{label}: stopped (PID {pid})"


def _registry_host(config: dict) -> str:
    """Resolve the registry bind host.

    Defaults to loopback so the control plane is not exposed on all interfaces.
    Set ECOSYSTEM_REGISTRY_HOST=0.0.0.0 only when the registry is firewalled
    to a trusted network.
    """
    return os.environ.get(
        "ECOSYSTEM_REGISTRY_HOST",
        config.get("registry", {}).get("host", "127.0.0.1"),
    )


def cmd_start() -> int:
    """Start the ecosystem registry."""
    config = _load_config()
    port = config.get("registry", {}).get("port", 8500)
    host = _registry_host(config)

    print(f"Starting ecosystem registry on {host}:{port}...")

    # Ensure data dir exists
    (ECOSYSTEM_DIR / "data").mkdir(exist_ok=True)

    proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn",
            "registry.app:app",
            "--host", host,
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

    try:
        pid = int(PID_FILE.read_text().strip())
    except ValueError:
        print("Registry PID file is corrupt - cleaning up")
        PID_FILE.unlink(missing_ok=True)
        return 1

    print(_terminate_pid(pid, "Registry"))
    PID_FILE.unlink(missing_ok=True)
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

    # Check registered services (signed so it works if read-auth is enabled)
    try:
        from ecosystem_auth.tokens import get_ecosystem_secret, sign_request
        services_url = f"{registry_url}/services"
        headers = sign_request("GET", services_url, get_ecosystem_secret())
        resp = httpx.get(services_url, timeout=3.0, headers=headers)
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
            cmd_parts = shlex.split(cmd)
            if cmd_parts and cmd_parts[0] == "python":
                cmd_parts[0] = sys.executable
            proc = subprocess.Popen(
                cmd_parts,
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

        try:
            pid = int(pid_file.read_text().strip())
        except ValueError:
            print(f"  {name}: corrupt PID file, cleaning up")
            pid_file.unlink(missing_ok=True)
            continue

        print(f"  {_terminate_pid(pid, name)}")
        pid_file.unlink(missing_ok=True)

    # Stop registry last
    cmd_stop()
    return 0


def cmd_restart() -> int:
    """Restart the ecosystem registry (stop if running, then start)."""
    if PID_FILE.exists():
        cmd_stop()
        # Brief pause so the port is released before re-binding.
        time.sleep(1.0)
    return cmd_start()


def cmd_monitor(interval: int = 5, once: bool = False) -> int:
    """Continuously display ecosystem health status.

    Refreshes every ``interval`` seconds until interrupted. With ``once``,
    renders a single snapshot and returns (useful for scripting/tests).
    """
    try:
        while True:
            # Clear screen for a live dashboard feel (skipped in --once mode).
            if not once:
                print("\033[2J\033[H", end="")
                print(f"Ecosystem monitor — refresh every {interval}s (Ctrl+C to exit)")
                print(f"Last update: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            cmd_status()
            if once:
                return 0
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nMonitor stopped.")
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
    host = _registry_host(config)
    python = sys.executable
    ecosystem_dir = str(ECOSYSTEM_DIR)
    supervisor = str(ECOSYSTEM_DIR / "scripts" / "process_manager.py")
    # Wrap uvicorn in the supervisor so macOS gets the same graceful-shutdown
    # and SIGKILL escalation behaviour as the Linux systemd unit.
    uvicorn_cmd = f"{python} -m uvicorn registry.app:app --host {host} --port {port}"

    plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{PLIST_NAME}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python}</string>
        <string>{supervisor}</string>
        <string>--cmd</string>
        <string>{uvicorn_cmd}</string>
        <string>--cwd</string>
        <string>{ecosystem_dir}</string>
        <string>--log</string>
        <string>{ecosystem_dir}/data/registry.log</string>
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


def cmd_secret(action: str, value: str | None = None) -> int:
    """Manage the shared ecosystem HMAC secret (file-backed, device-local).

    Actions: generate (create if absent), show (print for copying to another
    device), import <value> (set on this device), path (print the file location).
    """
    try:
        from ecosystem_auth.tokens import (
            ensure_ecosystem_secret, get_ecosystem_secret, write_secret, secret_file_path,
        )
    except Exception as e:  # pragma: no cover
        print(f"ecosystem_auth not available: {e}")
        return 1

    if action == "path":
        print(secret_file_path())
        return 0

    if action == "generate":
        secret = ensure_ecosystem_secret()
        print(f"Shared secret ready at {secret_file_path()}")
        print("\nTo join another device to this ecosystem, run there:")
        print(f"  ecosystem secret import {secret}")
        return 0

    if action == "import":
        if not value:
            print("Usage: ecosystem secret import <value>")
            return 1
        p = write_secret(value)
        print(f"Saved shared secret to {p}")
        return 0

    if action == "show":
        try:
            print(get_ecosystem_secret())
            return 0
        except Exception as e:
            print(str(e))
            return 1

    print(f"Unknown secret action: {action} (use generate|show|import|path)")
    return 1


def _device_apps() -> list[dict]:
    """Per-device enabled-apps record: which ecosystem apps are present here.

    An app is "present" (enabled on this device) when its repo directory exists
    under the resolved base path — the same signal the registry uses to decide
    what to pre-register. This is what makes subset / multi-device installs
    legible: apps absent here are simply hosted elsewhere (or not installed),
    not "broken"."""
    config = _load_config()
    apps = []
    for proj in _resolve_projects(config):
        apps.append({
            "key": proj["key"],
            "name": proj["name"],
            "present": Path(proj["abs_path"]).exists(),
            "path": str(proj["abs_path"]),
            "port": proj["port"],
        })
    return apps


def cmd_apps(as_json: bool = False) -> int:
    """List which ecosystem apps are installed/enabled on this device."""
    apps = _device_apps()
    if as_json:
        print(json.dumps(apps, indent=2))
        return 0

    present = [a for a in apps if a["present"]]
    absent = [a for a in apps if not a["present"]]
    print(f"Ecosystem apps on this device ({len(present)}/{len(apps)} present):\n")
    for a in apps:
        mark = "✓ present" if a["present"] else "· not here"
        print(f"  {mark}  {a['name']:<20} :{a['port']}  {a['path']}")
    if absent:
        print(
            f"\n{len(absent)} app(s) not installed here are expected on other "
            "devices (or simply not used) — this is normal for subset/networked "
            "deployments."
        )
    return 0


def cmd_partner(action: str, app_id: str | None = None, name: str | None = None,
                owner: str | None = None, service_names: str | None = None) -> int:
    """Manage third-party partner app credentials (per-app HMAC keys)."""
    from registry.app_store import AppStore
    store = AppStore()

    if action == "add":
        if not (app_id and name and owner and service_names):
            print("Usage: ecosystem partner add <app_id> --name <display> "
                  "--owner <contact> --service-names a,b")
            return 1
        names = [n.strip() for n in service_names.split(",") if n.strip()]
        try:
            rec, secret = store.add(app_id, name, owner, names)
        except ValueError as e:
            print(f"Error: {e}")
            return 1
        print(f"Created partner app '{rec['app_id']}' (owns: {', '.join(rec['owned_names'])})")
        print("Copy these now — the secret is shown only once:")
        print(f"  key_id: {rec['key_id']}")
        print(f"  secret: {secret}")
        return 0

    if action == "list":
        apps = store.list()
        if not apps:
            print("No partner apps registered.")
            return 0
        print(f"Partner apps ({len(apps)}):\n")
        for a in apps:
            print(f"  {a['status']:<9} {a['app_id']:<24} {a['display_name']:<18} "
                  f"owns={','.join(a['owned_names'])}  created={a['created_at']}")
        return 0

    if action == "show":
        if not app_id:
            print("Usage: ecosystem partner show <app_id>")
            return 1
        a = store.get(app_id)
        if not a:
            print(f"No such partner app: {app_id}")
            return 1
        for k in ("app_id", "key_id", "display_name", "owner", "owned_names",
                  "scopes", "status", "created_at"):
            print(f"  {k}: {a.get(k)}")
        return 0

    if action in ("suspend", "resume", "remove"):
        if not app_id:
            print(f"Usage: ecosystem partner {action} <app_id>")
            return 1
        if action == "remove":
            ok = store.remove(app_id)
        else:
            ok = store.set_status(app_id, "suspended" if action == "suspend" else "approved")
        if not ok:
            print(f"No such partner app: {app_id}")
            return 1
        if action == "remove":
            print(f"Partner app '{app_id}' removed.")
        else:
            print(f"Partner app '{app_id}' {action}d.")
        return 0

    print(f"Unknown partner action: {action} (use add|list|show|suspend|resume|remove)")
    return 1
