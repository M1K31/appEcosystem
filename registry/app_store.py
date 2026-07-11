"""Per-app credential store for third-party ecosystem participants.

JSON-file backed (mirrors registry.profile_store), 0600 (holds per-app HMAC
secrets), with mtime-based reload so a change made by the CLI process is seen
by the running registry without a restart (e.g. `partner suspend` revokes
immediately).
"""

import json
import logging
import os
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

RESERVED_NAMES = {
    "registry", "openeye", "aegissiem", "aegissiem_daemon",
    "ai_for_survival", "magicmirror",
}


def default_apps_path() -> str:
    return os.environ.get("ECOSYSTEM_APPS_FILE") or str(
        Path.home() / ".config" / "ecosystem" / "apps.json"
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _public(record: dict) -> dict:
    """A copy without the secret, for list/get views."""
    return {k: v for k, v in record.items() if k != "secret"}


class AppStore:
    def __init__(self, persistence_path: Optional[str] = None):
        self._path = persistence_path or default_apps_path()
        self._apps: dict[str, dict] = {}
        self._mtime: Optional[float] = None
        self._load()

    # ---- persistence -----------------------------------------------------
    def _load(self) -> None:
        try:
            p = Path(self._path)
            if not p.exists():
                self._apps = {}
                self._mtime = None
                return
            data = json.loads(p.read_text())
            self._apps = data if isinstance(data, dict) else {}
            self._mtime = p.stat().st_mtime
        except Exception as e:
            logger.warning("Failed to load app store (%s); starting empty", e)
            self._apps = {}
            self._mtime = None

    def _maybe_reload(self) -> None:
        try:
            m = os.path.getmtime(self._path)
        except OSError:
            return
        if m != self._mtime:
            self._load()

    def _persist(self) -> None:
        p = Path(self._path)
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".apps.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(self._apps, f, indent=2)
            os.chmod(tmp, 0o600)
            os.replace(tmp, p)
            os.chmod(p, 0o600)
            self._mtime = p.stat().st_mtime
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    # ---- API -------------------------------------------------------------
    def add(self, app_id: str, display_name: str, owner: str,
            owned_names: list[str], scopes: Optional[list[str]] = None) -> tuple[dict, str]:
        self._maybe_reload()
        if app_id in self._apps:
            raise ValueError(f"app_id '{app_id}' already exists")
        taken = self.all_owned_names()
        for n in owned_names:
            if n in RESERVED_NAMES:
                raise ValueError(f"'{n}' is a reserved first-party service name")
            if n in taken:
                raise ValueError(f"service name '{n}' is already owned by another app")
        secret = secrets.token_urlsafe(32)
        record = {
            "app_id": app_id,
            "key_id": "k_" + secrets.token_urlsafe(12),
            "secret": secret,
            "display_name": display_name,
            "owner": owner,
            "owned_names": list(owned_names),
            "scopes": list(scopes) if scopes is not None else ["register:self"],
            "status": "approved",
            "created_at": _now_iso(),
            "approved_at": _now_iso(),
        }
        self._apps[app_id] = record
        self._persist()
        return _public(record), secret

    def get(self, app_id: str) -> Optional[dict]:
        self._maybe_reload()
        rec = self._apps.get(app_id)
        return _public(rec) if rec else None

    def get_by_key_id(self, key_id: str) -> Optional[dict]:
        self._maybe_reload()
        for rec in self._apps.values():
            if rec.get("key_id") == key_id and rec.get("status") == "approved":
                return dict(rec)  # full record incl. secret
        return None

    def list(self) -> list[dict]:
        self._maybe_reload()
        return [_public(r) for r in self._apps.values()]

    def set_status(self, app_id: str, status: str) -> bool:
        self._maybe_reload()
        rec = self._apps.get(app_id)
        if not rec:
            return False
        rec["status"] = status
        self._persist()
        return True

    def remove(self, app_id: str) -> bool:
        self._maybe_reload()
        if app_id not in self._apps:
            return False
        del self._apps[app_id]
        self._persist()
        return True

    def all_owned_names(self) -> set[str]:
        names: set[str] = set()
        for rec in self._apps.values():
            names.update(rec.get("owned_names", []))
        return names
