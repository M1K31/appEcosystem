"""Pure helpers shared by the hub's command dispatcher and the provider-side receiver."""
from __future__ import annotations

import hashlib
import json
from typing import Any

FINAL_STATUSES = frozenset({"completed", "denied", "failed", "provider_unavailable"})
OPEN_STATUSES = frozenset({"received", "dispatching", "accepted", "pending_approval"})
MAX_JSON_BYTES = 64 * 1024


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def request_digest(capability: str, target: dict[str, Any], parameters: dict[str, Any]) -> str:
    """SHA-256 of what a command asks for; identical requests share a digest whatever their key order."""
    body = {"capability": capability, "target": target or {}, "parameters": parameters or {}}
    return hashlib.sha256(_canonical(body)).hexdigest()


def json_too_large(value: Any) -> bool:
    """True when `value` serialises to more than MAX_JSON_BYTES of compact JSON."""
    try:
        size = len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError):
        return True
    return size > MAX_JSON_BYTES
