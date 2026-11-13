"""Cross-platform single-host advisory lock preventing duplicate local Hub instances."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any


def default_hub_lock_path() -> Path:
    override = (os.environ.get("ECOSYSTEM_HUB_LOCK_FILE") or "").strip()
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
        return base / "Ecosystem" / "hub-host.lock"
    return Path.home() / ".local" / "share" / "ecosystem" / "hub-host.lock"


def _try_flock(fd: int) -> bool:
    if sys.platform == "win32":
        import msvcrt

        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False
    else:
        import fcntl

        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            return False


def _unlock_fd(fd: int) -> None:
    if sys.platform == "win32":
        import msvcrt

        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
    else:
        import fcntl

        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass


class SingleHostLock:
    """Process-bound advisory file lock ensuring at most one embedded Hub per machine."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path is not None else default_hub_lock_path()
        self._fd: int | None = None
        self._metadata: dict[str, Any] | None = None

    @property
    def is_held(self) -> bool:
        return self._fd is not None

    @property
    def metadata(self) -> dict[str, Any] | None:
        return dict(self._metadata) if self._metadata else None

    def acquire(
        self,
        *,
        app_name: str,
        hub_url: str,
        priority: int = 0,
        pid: int | None = None,
    ) -> bool:
        """Attempt to acquire the single-host lock without blocking."""
        if self._fd is not None:
            return True

        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_CREAT | os.O_RDWR
        fd = os.open(str(self.path), flags, 0o600)
        if not _try_flock(fd):
            os.close(fd)
            return False

        meta = {
            "app_name": app_name,
            "pid": os.getpid() if pid is None else int(pid),
            "priority": int(priority),
            "hub_url": hub_url,
            "acquired_at": time.time(),
        }
        payload = json.dumps(meta, indent=2).encode("utf-8")
        try:
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, payload)
            os.fsync(fd)
        except OSError:
            pass

        self._fd = fd
        self._metadata = meta
        return True

    def release(self) -> None:
        """Release the advisory lock if currently held by this instance."""
        if self._fd is None:
            return
        fd = self._fd
        self._fd = None
        self._metadata = None
        try:
            os.ftruncate(fd, 0)
        except OSError:
            pass
        _unlock_fd(fd)
        try:
            os.close(fd)
        except OSError:
            pass

    def inspect_owner(self) -> dict[str, Any] | None:
        """Read current lock owner metadata without blocking (or None if unlocked/empty)."""
        if self._metadata is not None:
            return dict(self._metadata)
        try:
            if not self.path.is_file():
                return None
            raw = self.path.read_text(encoding="utf-8").strip()
            if not raw:
                return None
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else None
        except Exception:
            return None

    def __enter__(self) -> SingleHostLock:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()

