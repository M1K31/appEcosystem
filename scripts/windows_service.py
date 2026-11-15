"""Windows Service wrapper for the appEcosystem Hub/Registry (pywin32 or foreground mode).

Usage on Windows:
    python scripts\\windows_service.py install
    python scripts\\windows_service.py start
    python scripts\\windows_service.py stop
    python scripts\\windows_service.py remove
    python scripts\\windows_service.py run     # foreground mode (also used by NSSM)
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

SERVICE_NAME = "EcosystemHubService"
SERVICE_DISPLAY = "appEcosystem Hub & Service Registry"
SERVICE_DESC = "Local-first service discovery, capability registry, policy hub, and notification router."


def _runtime_env() -> tuple[Path, dict[str, str], str, int]:
    repo_root = Path(__file__).resolve().parent.parent
    local_app_data = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
    data_dir = local_app_data / "Ecosystem" / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env.setdefault("ECOSYSTEM_CONFIG", str(repo_root / "ecosystem.yaml"))
    env.setdefault("ECOSYSTEM_MODE", "local")
    env.setdefault("ECOSYSTEM_REGISTRY_FILE", str(data_dir / "registry.json"))
    env.setdefault("ECOSYSTEM_AI_PROFILE_FILE", str(data_dir / "ai_profile.json"))
    env.setdefault("ECOSYSTEM_CAPABILITIES_FILE", str(data_dir / "capabilities.json"))
    env.setdefault("ECOSYSTEM_NOTIFICATIONS_DB", str(data_dir / "notifications.db"))

    mode = env.get("ECOSYSTEM_MODE", "local")
    bind_host = env.get("ECOSYSTEM_REGISTRY_HOST") or ("0.0.0.0" if mode == "lan" else "127.0.0.1")
    port = int(env.get("ECOSYSTEM_REGISTRY_PORT", "8500"))
    return repo_root, env, bind_host, port


def run_foreground() -> int:
    repo_root, env, bind_host, port = _runtime_env()
    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "registry.app:app",
        "--host",
        bind_host,
        "--port",
        str(port),
    ]
    return subprocess.call(cmd, cwd=str(repo_root), env=env)


def _define_pywin32_service():
    import servicemanager  # type: ignore[import-not-found]
    import win32event  # type: ignore[import-not-found]
    import win32service  # type: ignore[import-not-found]
    import win32serviceutil  # type: ignore[import-not-found]

    class EcosystemWindowsService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY
        _svc_description_ = SERVICE_DESC

        def __init__(self, args):
            super().__init__(args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
            self._proc: subprocess.Popen | None = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.stop_event)
            if self._proc and self._proc.poll() is None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    self._proc.kill()

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            repo_root, env, bind_host, port = _runtime_env()
            cmd = [
                sys.executable,
                "-m",
                "uvicorn",
                "registry.app:app",
                "--host",
                bind_host,
                "--port",
                str(port),
            ]
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            self._proc = subprocess.Popen(
                cmd,
                cwd=str(repo_root),
                env=env,
                creationflags=creationflags,
            )
            while self._proc.poll() is None:
                rc = win32event.WaitForSingleObject(self.stop_event, 1000)
                if rc == win32event.WAIT_OBJECT_0:
                    break

    return win32serviceutil, EcosystemWindowsService


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0].lower() == "run":
        return run_foreground()

    if sys.platform != "win32":
        sys.stderr.write("windows_service.py service commands require Windows (use 'run' for foreground test).\n")
        return 1

    try:
        win32serviceutil, svc_cls = _define_pywin32_service()
    except ImportError:
        sys.stderr.write(
            "pywin32 is not installed. Either install pywin32 in the ecosystem venv "
            "or register 'windows_service.py run' via NSSM (see scripts/install-windows.ps1).\n"
        )
        return 2

    win32serviceutil.HandleCommandLine(svc_cls)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

