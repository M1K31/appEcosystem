"""Shared AI profile store for the registry.

Holds the single ecosystem-wide AI/LLM profile (provider, selected model, cloud
toggles, routing). Any app can read it (`GET /ai-profile`) and write changes
(`PUT /ai-profile`); writes bump the version and trigger an
`ecosystem.ai_profile_changed` event so other apps update live. That is what
makes an LLM selection in one app appear in all the others.

The store works on plain dicts and seeds its default from `ecosystem_ai` when
available, falling back to an embedded default so the registry never fails to
boot over an optional AI dependency.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


def _embedded_default() -> dict[str, Any]:
    return {
        "default_provider": "ollama",
        "selected_model": "auto",
        "ollama_base_url": "http://localhost:11434",
        "models_dir": "",
        "task_models": {"chat": "auto", "embed": "nomic-embed-text", "vision": "auto"},
        "cloud": {
            "anthropic": {"enabled": False, "model": ""},
            "openai": {"enabled": False, "model": ""},
            "gemini": {"enabled": False, "model": ""},
        },
        "prefer": "local",
        "allow_cloud_fallback": True,
        "version": 1,
        "updated_at": time.time(),
        "updated_by": "",
    }


def default_profile_dict() -> dict[str, Any]:
    """Default profile, preferring the shared ecosystem_ai schema if installed."""
    try:
        from ecosystem_ai.profile import default_profile
        return default_profile().to_dict()
    except Exception:
        return _embedded_default()


# Top-level fields a client is allowed to change via PUT (no version/timestamps).
_WRITABLE = {
    "default_provider", "selected_model", "ollama_base_url", "models_dir",
    "task_models", "cloud", "prefer", "allow_cloud_fallback",
}


class AIProfileStore:
    """In-memory AI profile with JSON persistence and last-write-wins versioning."""

    def __init__(self, persistence_path: Optional[str] = None):
        self._path = persistence_path
        self._profile = default_profile_dict()
        if persistence_path:
            self._load()

    def get(self) -> dict[str, Any]:
        return dict(self._profile)

    def update(self, changes: dict[str, Any], updated_by: str = "") -> dict[str, Any]:
        """Apply writable changes, bump version, persist, and return the profile."""
        applied = {k: v for k, v in (changes or {}).items() if k in _WRITABLE}
        self._profile.update(applied)
        self._profile["version"] = int(self._profile.get("version", 0)) + 1
        self._profile["updated_at"] = time.time()
        self._profile["updated_by"] = updated_by
        self._persist()
        logger.info(
            "AI profile updated to v%s by %s (%s)",
            self._profile["version"], updated_by or "unknown", ", ".join(applied) or "no-op",
        )
        return self.get()

    def _persist(self) -> None:
        if not self._path:
            return
        try:
            p = Path(self._path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(self._profile, indent=2, default=str))
        except Exception as e:
            logger.error("Failed to persist AI profile: %s", e)

    def _load(self) -> None:
        try:
            p = Path(self._path)
            if p.exists():
                data = json.loads(p.read_text())
                if isinstance(data, dict):
                    # Start from defaults so new fields are present, then overlay.
                    merged = default_profile_dict()
                    merged.update(data)
                    self._profile = merged
                    logger.info("Loaded AI profile v%s", self._profile.get("version"))
        except Exception as e:
            logger.error("Failed to load AI profile: %s", e)
