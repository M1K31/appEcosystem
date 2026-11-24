"""Recorded floor-passes store for analyst models.

Persists the set of models that have passed the standard floor benchmark suite.
Resolution order for the backing file:
  1. Explicit ``path`` passed to load/save
  2. ``$ECOSYSTEM_FLOOR_PASSES_PATH``
  3. ``~/.config/ecosystem/floor_passes.json``
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def get_floor_passes_path() -> Path:
    env_path = os.getenv("ECOSYSTEM_FLOOR_PASSES_PATH")
    if env_path:
        return Path(env_path)
    base = Path.home() / ".config" / "ecosystem"
    return base / "floor_passes.json"


def load_recorded_floor_passes(path: Path | str | None = None) -> set[str]:
    """Load recorded floor passes. A missing or corrupt file returns an empty set."""
    p = Path(path) if path is not None else get_floor_passes_path()
    if not p.exists():
        return set()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return {str(item) for item in data}
        if isinstance(data, dict):
            return {str(item) for item in data.get("passes", [])}
    except Exception as exc:
        logger.warning("Could not read floor passes from %s: %s", p, exc)
    return set()


def record_floor_pass(model: str, path: Path | str | None = None) -> None:
    """Record that a model has passed the floor benchmark suite."""
    p = Path(path) if path is not None else get_floor_passes_path()
    passes = load_recorded_floor_passes(p)
    passes.add(model)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(sorted(passes), indent=2), encoding="utf-8")


def clear_recorded_floor_passes(path: Path | str | None = None) -> None:
    """Remove recorded floor passes file (for testing / reset)."""
    p = Path(path) if path is not None else get_floor_passes_path()
    if p.exists():
        try:
            p.unlink()
        except OSError as exc:
            logger.warning("Could not remove floor passes at %s: %s", p, exc)
