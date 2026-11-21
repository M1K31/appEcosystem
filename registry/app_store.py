"""Per-app credential store for third-party ecosystem participants.

JSON-file backed (mirrors registry.profile_store), 0600 (holds per-app HMAC
secrets), with mtime-based reload so a change made by the CLI process is seen
by the running registry without a restart (e.g. `partner suspend` revokes
immediately).
"""

import contextlib
import functools
import json
import logging
import os
import re
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

try:
    import fcntl
except ImportError:  # pragma: no cover - POSIX only; Windows degrades to best-effort
    fcntl = None  # type: ignore[assignment]

# App ids: a conservative, shell/URL-safe shape. A leading alphanumeric bars the
# reserved `__owner__` principal (and any `__`-prefixed internal id) from being
# claimed by a registered or self-registered app.
_APP_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
# Characters that would turn an owned service name into a wildcard. `*` in
# particular is the shared-secret owner's "owns everything" marker and must
# never be held by an app key.
_WILDCARD_CHARS = set("*?[]")


def _locked(method):
    """Run a writer under the store's exclusive cross-process lock (fresh load inside it)."""
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._write_lock():
            return method(self, *args, **kwargs)
    return wrapper


def validate_app_id(app_id: str) -> None:
    """Raise ValueError unless `app_id` is well-formed and not a reserved internal id."""
    if not isinstance(app_id, str) or not _APP_ID_RE.match(app_id) or app_id.startswith("__"):
        raise ValueError(
            "app_id must be 1–128 chars of letters, digits, '.', '_' or '-', start alphanumeric, "
            "and not begin with '__'"
        )

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
    # A cap on self-registered pending records, so the open registration route
    # cannot be used to fill the store with junk. The owner prunes with `reject`.
    MAX_PENDING = 50

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

    @contextlib.contextmanager
    def _write_lock(self) -> Iterator[None]:
        """Hold an exclusive cross-process lock and reload fresh for a read-modify-write.

        Every writer runs under this so a concurrent writer in another process
        (the CLI vs the running registry) cannot interleave: the lock is taken,
        the latest file is loaded inside it, the mutation and `_persist` run, then
        the lock is released. Locking only the `os.replace` in `_persist` would
        still let a stale in-memory copy overwrite another process's write.
        """
        if fcntl is None:  # Windows / no fcntl: best-effort, single-process correctness only
            self._load()
            yield
            return
        lock_path = Path(self._path).with_suffix(".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(lock_path, "a+")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            self._load()  # the authoritative on-disk state, under the lock
            yield
        finally:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally:
                handle.close()

    # ---- API -------------------------------------------------------------
    def _check_names(self, owned_names: list[str], *, first_party: bool, exclude_app_id: Optional[str] = None) -> None:
        """Reserved first-party names are refused unless `first_party`; names owned by another app are refused."""
        taken = {n for app_id, rec in self._apps.items()
                 if app_id != exclude_app_id for n in rec.get("owned_names", [])}
        for n in owned_names:
            if not n or set(n) & _WILDCARD_CHARS:
                # '*' is the shared-secret owner's wildcard; an app key must never hold it.
                raise ValueError(f"service name {n!r} may not be empty or contain a wildcard")
            if n in RESERVED_NAMES and not first_party:
                raise ValueError(f"'{n}' is a reserved first-party service name")
            if n in taken:
                raise ValueError(f"service name '{n}' is already owned by another app")

    @_locked
    def add(self, app_id: str, display_name: str, owner: str,
            owned_names: list[str], scopes: Optional[list[str]] = None,
            *, first_party: bool = False) -> tuple[dict, str]:
        """Create an approved app key. `first_party=True` lets it own a reserved name (it IS that app)."""
        validate_app_id(app_id)
        self._maybe_reload()
        if app_id in self._apps:
            raise ValueError(f"app_id '{app_id}' already exists")
        self._check_names(owned_names, first_party=first_party)
        secret = secrets.token_urlsafe(32)
        record = {
            "app_id": app_id,
            "key_id": "k_" + secrets.token_urlsafe(12),
            "secret": secret,
            "display_name": display_name,
            "owner": owner,
            "owned_names": list(owned_names),
            "scopes": list(scopes) if scopes is not None else ["register:self"],
            "first_party": bool(first_party),
            "status": "approved",
            "created_at": _now_iso(),
            "approved_at": _now_iso(),
        }
        self._apps[app_id] = record
        self._persist()
        return _public(record), secret

    @_locked
    def register_self(self, app_id: str, display_name: str, owner: str = "",
                      requested_names: Optional[list[str]] = None,
                      requested_scopes: Optional[list[str]] = None) -> tuple[dict, str]:
        """Self-service registration: create a PENDING key with no grants.

        Anyone running a third-party app can call this to obtain a key, but the
        key authenticates nothing (`get_by_key_id` returns None for a pending
        record) until the owner `approve`s it and assigns names and scopes. The
        requested names/scopes are recorded only as a hint for that review. An
        existing app_id is never overwritten here, so the open route cannot
        reset an approved app's key.
        """
        validate_app_id(app_id)
        self._maybe_reload()
        if app_id in self._apps:
            raise ValueError(f"app_id '{app_id}' already exists")
        pending = sum(1 for r in self._apps.values() if r.get("status") == "pending")
        if pending >= self.MAX_PENDING:
            raise ValueError("too many pending registrations; the owner must approve or reject some first")
        secret = secrets.token_urlsafe(32)
        record = {
            "app_id": app_id,
            "key_id": "k_" + secrets.token_urlsafe(12),
            "secret": secret,
            "display_name": display_name,
            "owner": owner,
            "owned_names": [],
            "scopes": [],
            "first_party": False,
            "requested_names": list(requested_names or []),
            "requested_scopes": list(requested_scopes or []),
            "status": "pending",
            "created_at": _now_iso(),
        }
        self._apps[app_id] = record
        self._persist()
        return _public(record), secret

    @_locked
    def approve(self, app_id: str, owned_names: list[str], scopes: list[str],
                *, first_party: bool = False) -> dict:
        """Owner action: grant a pending (or existing) app its names and scopes and activate it."""
        self._maybe_reload()
        rec = self._apps.get(app_id)
        if rec is None:
            raise ValueError(f"app_id '{app_id}' not found")
        self._check_names(owned_names, first_party=first_party, exclude_app_id=app_id)
        rec["owned_names"] = list(owned_names)
        rec["scopes"] = list(scopes)
        rec["first_party"] = bool(first_party)
        rec["status"] = "approved"
        rec["approved_at"] = _now_iso()
        self._persist()
        return _public(rec)

    def reject(self, app_id: str) -> bool:
        """Owner action: remove a registration (pending or otherwise)."""
        return self.remove(app_id)

    def get(self, app_id: str) -> Optional[dict]:
        self._maybe_reload()
        rec = self._apps.get(app_id)
        return _public(rec) if rec else None

    def get_by_key_id(self, key_id: str) -> Optional[dict]:
        self._maybe_reload()
        for app_id, rec in self._apps.items():
            if rec.get("key_id") != key_id or rec.get("status") != "approved":
                continue
            # Quarantine a record whose id is malformed or reserved: a legacy or
            # hand-edited apps.json could carry an id like "__owner__" that the
            # creation-time validation never saw, and resolving it would hand a
            # key the owner principal. Such a record authenticates nothing.
            try:
                validate_app_id(app_id)
                validate_app_id(str(rec.get("app_id", "")))
            except ValueError:
                logger.warning("Ignoring app record with an invalid id: %r", app_id)
                return None
            return dict(rec)  # full record incl. secret
        return None

    def list(self) -> list[dict]:
        self._maybe_reload()
        return [_public(r) for r in self._apps.values()]

    @_locked
    def set_status(self, app_id: str, status: str) -> bool:
        """Change an existing app's status (e.g. suspend/resume).

        A pending registration is NOT activated this way: only `approve` grants
        it names and scopes, which is where the owner reviews it. Resuming a
        pending record would otherwise make it `approved` with no grants and no
        review.
        """
        validate_app_id(app_id)
        self._maybe_reload()
        rec = self._apps.get(app_id)
        if not rec:
            return False
        if rec.get("status") == "pending" and status != "pending":
            raise ValueError("a pending registration must be approved (not resumed) to activate it")
        rec["status"] = status
        self._persist()
        return True

    @_locked
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
