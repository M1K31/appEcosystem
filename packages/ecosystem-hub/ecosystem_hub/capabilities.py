"""Project-contributed capability registry with explicit withdrawal & unavailability reasons."""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ecosystem_client.contracts import assert_valid_schema


@dataclass(frozen=True)
class CapabilityResolution:
    """Result of resolving a capability name for an automation, UI control, or voice intent."""

    capability: str
    available: bool
    providers: list[dict[str, Any]] = field(default_factory=list)
    unavailable_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "available": self.available,
            "providers": self.providers,
            "unavailable_reason": self.unavailable_reason,
        }


class CapabilityRegistry:
    """Stores validated capability-manifest.v1 entries and tracks provider availability.

    Invariant: when a provider deregisters, withdraws, or fails health checks, dependent
    capabilities report `available=False` with an explicit `unavailable_reason` rather
    than silently disappearing or granting another provider expanded authority.
    """

    def __init__(self, persistence_path: str | Path | None = None):
        self._path = Path(persistence_path) if persistence_path else None
        self._lock = threading.RLock()
        # Keyed by f"{capability}::{provider.app}::{provider.device_id}"
        self._records: dict[str, dict[str, Any]] = {}
        if self._path:
            self._load()

    @staticmethod
    def _key(capability: str, app: str, device_id: str) -> str:
        return f"{capability}::{app}::{device_id}"

    def _load(self) -> None:
        if not self._path or not self._path.is_file():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                self._records = data
        except Exception:
            self._records = {}

    def _persist(self) -> None:
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(
            dir=str(self._path.parent),
            prefix=".capabilities.",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._records, fh, indent=2)
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.replace(tmp, self._path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def register(self, manifest: dict[str, Any]) -> dict[str, Any]:
        """Validate against capability-manifest.v1 and upsert as an active capability."""
        assert_valid_schema(manifest, "capability-manifest.v1")
        cap = manifest["capability"]
        provider = manifest["provider"]
        app = provider["app"]
        device_id = provider["device_id"]
        now = time.time()

        with self._lock:
            k = self._key(cap, app, device_id)
            prev = self._records.get(k)
            record = {
                "manifest": dict(manifest),
                "capability": cap,
                "app": app,
                "device_id": device_id,
                "action_class": manifest["action_class"],
                "status": "active",
                "unavailable_reason": None,
                "registered_at": prev["registered_at"] if prev else now,
                "updated_at": now,
            }
            self._records[k] = record
            self._persist()
            return dict(record)

    def register_many(self, manifests: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [self.register(m) for m in manifests]

    def withdraw(
        self,
        capability: str,
        app: str,
        *,
        device_id: str | None = None,
        reason: str | None = None,
    ) -> int:
        """Mark matching capability record(s) withdrawn with a clear reason."""
        now = time.time()
        count = 0
        with self._lock:
            for rec in self._records.values():
                if rec["capability"] != capability or rec["app"] != app:
                    continue
                if device_id is not None and rec["device_id"] != device_id:
                    continue
                if rec["status"] != "withdrawn":
                    rec["status"] = "withdrawn"
                    rec["unavailable_reason"] = (
                        reason or f"Capability '{capability}' withdrawn by provider '{app}'"
                    )
                    rec["updated_at"] = now
                    count += 1
            if count:
                self._persist()
        return count

    def withdraw_provider(
        self,
        app: str,
        *,
        device_id: str | None = None,
        reason: str | None = None,
    ) -> list[dict[str, Any]]:
        """Withdraw all active capabilities owned by a deregistering or unhealthy provider."""
        now = time.time()
        affected: list[dict[str, Any]] = []
        with self._lock:
            for rec in self._records.values():
                if rec["app"] != app:
                    continue
                if device_id is not None and rec["device_id"] != device_id:
                    continue
                if rec["status"] == "active":
                    rec["status"] = "withdrawn"
                    rec["unavailable_reason"] = (
                        reason or f"Provider '{app}' ({rec['device_id']}) is offline or deregistered"
                    )
                    rec["updated_at"] = now
                    affected.append(dict(rec))
            if affected:
                self._persist()
        return affected

    def list_capabilities(
        self,
        *,
        action_class: str | None = None,
        app: str | None = None,
        capability: str | None = None,
        active_only: bool = True,
    ) -> list[dict[str, Any]]:
        with self._lock:
            out: list[dict[str, Any]] = []
            for rec in self._records.values():
                if active_only and rec["status"] != "active":
                    continue
                if action_class and rec["action_class"] != action_class:
                    continue
                if app and rec["app"] != app:
                    continue
                if capability and rec["capability"] != capability:
                    continue
                out.append(dict(rec))
            return sorted(out, key=lambda r: (r["capability"], r["app"], r["device_id"]))

    def resolve(self, capability: str) -> CapabilityResolution:
        """Resolve healthy providers for `capability` or explain why it is unavailable."""
        with self._lock:
            matching = [r for r in self._records.values() if r["capability"] == capability]
            if not matching:
                return CapabilityResolution(
                    capability=capability,
                    available=False,
                    providers=[],
                    unavailable_reason=f"No installed project has registered capability '{capability}'",
                )
            active = [dict(r) for r in matching if r["status"] == "active"]
            if active:
                return CapabilityResolution(
                    capability=capability,
                    available=True,
                    providers=active,
                    unavailable_reason=None,
                )
            reasons = sorted(
                {
                    r.get("unavailable_reason") or f"Provider '{r['app']}' unavailable"
                    for r in matching
                }
            )
            return CapabilityResolution(
                capability=capability,
                available=False,
                providers=[],
                unavailable_reason="; ".join(reasons),
            )

