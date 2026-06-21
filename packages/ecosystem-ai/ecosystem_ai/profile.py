"""Shared ecosystem AI profile.

This is the canonical AI/LLM configuration for the whole ecosystem. The registry
holds it; every app reads it on startup/refresh and may write changes back. That
is what makes a selection made in one app appear in all the others: the profile
is a single shared source of truth (last-write-wins via `version`/`updated_at`),
with a `profile changed` event letting apps update live. When the registry is
absent, each app falls back to its local profile (standalone).
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class CloudProvider:
    enabled: bool = False
    model: str = ""


@dataclass
class AIProfile:
    # Default provider for the ecosystem. Ollama-first (local, private, free).
    default_provider: str = "ollama"

    # The user's currently selected chat model. "auto" => resolve from the
    # local hardware tier. This is the primary value that syncs across apps.
    selected_model: str = "auto"

    ollama_base_url: str = "http://localhost:11434"
    models_dir: str = ""  # one shared model store; blank = provider default

    # Per task-class model overrides ("auto" => tier default / provider default).
    task_models: dict[str, str] = field(
        default_factory=lambda: {"chat": "auto", "embed": "nomic-embed-text", "vision": "auto"}
    )

    # Opt-in cloud/agentic providers (keys come from env/secrets, never here).
    cloud: dict[str, CloudProvider] = field(
        default_factory=lambda: {
            "anthropic": CloudProvider(),
            "openai": CloudProvider(),
            "gemini": CloudProvider(),
        }
    )

    # Routing policy.
    prefer: str = "local"            # "local" | "cloud" | "quality"
    allow_cloud_fallback: bool = True

    # Sync metadata (last-write-wins).
    version: int = 1
    updated_at: float = field(default_factory=time.time)
    updated_by: str = ""

    # ------------------------------------------------------------------ #
    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["cloud"] = {k: asdict(v) for k, v in self.cloud.items()}
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AIProfile":
        data = dict(data or {})
        cloud_raw = data.pop("cloud", None)
        prof = cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
        if isinstance(cloud_raw, dict):
            prof.cloud = {
                name: CloudProvider(**{k: v for k, v in (cfg or {}).items()
                                       if k in CloudProvider.__dataclass_fields__})
                for name, cfg in cloud_raw.items()
            }
        return prof

    def merge(self, overrides: dict[str, Any]) -> "AIProfile":
        """Return a copy with non-None overrides applied (local over shared)."""
        base = self.to_dict()
        for k, v in (overrides or {}).items():
            if v is not None and k in base:
                base[k] = v
        return AIProfile.from_dict(base)

    def with_change(self, *, updated_by: str = "", **changes: Any) -> "AIProfile":
        """Apply changes, bump the version, and stamp the writer (for sync)."""
        data = self.to_dict()
        for k, v in changes.items():
            if k in data:
                data[k] = v
        prof = AIProfile.from_dict(data)
        prof.version = self.version + 1
        prof.updated_at = time.time()
        prof.updated_by = updated_by
        return prof


def default_profile() -> AIProfile:
    """The ecosystem default profile: Ollama-first, cloud opt-in."""
    return AIProfile()
