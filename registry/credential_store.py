"""File-backed storage for cloud AI provider API keys.

Keys live in ~/.config/ecosystem/provider_keys.json at mode 0600 — deliberately
NOT in ai_profile.json, which syncs across apps and is safe to read broadly.
Only `get_key` ever returns a secret; `status()` is the shape every API and UI
surfaces, and it exposes nothing beyond the last four characters.

Concurrency contract: the registry, the CLI, and a UI-driven API can all write
this file as independent OS processes. Writes are made atomic (temp file +
os.replace) so a crash mid-write can never leave a truncated/corrupt file, and
set_key/delete_key hold an advisory file lock across their whole
read-modify-write sequence so two processes touching different providers at
the same time cannot clobber each other's changes (lost-update race).
"""
from __future__ import annotations

import contextlib
import datetime
import json
import os
import pathlib
from typing import Optional

try:
    import fcntl
except ImportError:  # pragma: no cover - POSIX-only lock, degrade gracefully elsewhere
    fcntl = None  # type: ignore[assignment]

SUPPORTED_PROVIDERS = ("anthropic", "openai", "gemini")


def default_path() -> pathlib.Path:
    return pathlib.Path(
        os.environ.get("ECOSYSTEM_PROVIDER_KEYS_FILE", "")
        or (pathlib.Path.home() / ".config" / "ecosystem" / "provider_keys.json")
    )


class ProviderCredentialStore:
    def __init__(self, path: Optional[str] = None):
        self._path = pathlib.Path(path) if path else default_path()

    def _read(self) -> dict:
        try:
            with open(self._path) as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except FileNotFoundError:
            # Genuinely normal: nothing has been configured yet.
            return {}
        except json.JSONDecodeError:
            # Don't let the default message through - it can echo the
            # offending line, which may contain key material. Name only
            # the path.
            raise ValueError(
                f"Provider credential store at {self._path} is corrupt (invalid JSON)"
            ) from None
        # Any other OSError (PermissionError, etc.) is a real failure and
        # must propagate - it must never be indistinguishable from "not
        # configured yet", since status() is the only view the API/CLI/UI get.

    def _write(self, data: dict) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write: build the new contents in a temp file in the SAME
        # directory (so os.replace stays on one filesystem and is atomic on
        # POSIX), then swap it into place. This means a process that dies
        # mid-write leaves the original file untouched instead of truncated
        # - a truncated file would read back as {} and silently erase every
        # other provider's key.
        tmp_path = self._path.with_name(f".{self._path.name}.tmp-{os.getpid()}")
        # Create with 0600 from the start so the key is never briefly
        # world-readable - even in the temp file.
        fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(str(tmp_path), str(self._path))
        except BaseException:
            with contextlib.suppress(OSError):
                os.remove(str(tmp_path))
            raise

    @contextlib.contextmanager
    def _locked(self):
        """Advisory lock serializing read-modify-write across processes.

        Three independent processes (registry, CLI, UI-driven API) can call
        set_key/delete_key concurrently for different providers. Without a
        lock spanning read -> modify -> write, two such calls can each read
        the same starting state and the second write silently discards the
        first (lost update). fcntl.flock on a sidecar lock file serializes
        that whole sequence. POSIX-only, best-effort: if fcntl isn't
        available we skip locking rather than crash.
        """
        if fcntl is None:
            yield
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self._path.with_name(f"{self._path.name}.lock")
        fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    @staticmethod
    def _validate(provider: str) -> str:
        if provider not in SUPPORTED_PROVIDERS:
            raise ValueError(
                f"Unknown provider {provider!r}. Supported: {', '.join(SUPPORTED_PROVIDERS)}"
            )
        return provider

    def set_key(self, provider: str, key: str) -> None:
        self._validate(provider)
        key = (key or "").strip()
        if not key:
            raise ValueError("Refusing to store an empty API key")

        with self._locked():
            data = self._read()
            data[provider] = {
                "key": key,
                "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
            self._write(data)

    def get_key(self, provider: str) -> Optional[str]:
        entry = self._read().get(provider) or {}
        return entry.get("key") or None

    def delete_key(self, provider: str) -> bool:
        self._validate(provider)
        with self._locked():
            data = self._read()
            if provider not in data:
                return False
            del data[provider]
            self._write(data)
            return True

    def status(self) -> dict[str, dict]:
        """Non-secret view: what every API response and UI renders."""
        data = self._read()
        out: dict[str, dict] = {}
        for name in SUPPORTED_PROVIDERS:
            entry = data.get(name) or {}
            key = entry.get("key") or ""
            out[name] = {
                "configured": bool(key),
                "last4": key[-4:] if key else "",
                "updated_at": entry.get("updated_at", ""),
            }
        return out
