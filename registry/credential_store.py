"""File-backed storage for cloud AI provider API keys.

Keys live in ~/.config/ecosystem/provider_keys.json at mode 0600 — deliberately
NOT in ai_profile.json, which syncs across apps and is safe to read broadly.
Only `get_key` ever returns a secret; `status()` is the shape every API and UI
surfaces, and it exposes nothing beyond the last four characters.
"""
from __future__ import annotations

import datetime
import json
import os
import pathlib
from typing import Optional

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
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {}

    def _write(self, data: dict) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # Create with 0600 from the start so the key is never briefly world-readable.
        fd = os.open(str(self._path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)

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
