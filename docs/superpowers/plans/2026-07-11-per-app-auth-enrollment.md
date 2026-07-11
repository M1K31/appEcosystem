# Per-App Credentials + Name Ownership (Phase 1) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give third-party apps their own HMAC credentials bound to the service names they may manage, enforced by the registry, without changing how existing first-party apps authenticate.

**Architecture:** A JSON-file `AppStore` (mirrors `AIProfileStore`, with mtime-based live reload so `suspend` takes effect without a registry restart) holds per-app records. The `ecosystem_auth` middleware is refactored so its verification logic lives in a plain `authenticate_request(request, credentials, key_resolver=None)` helper; `require_ecosystem_auth` stays a thin, signature-unchanged FastAPI dependency delegating with `key_resolver=None`. The registry injects a resolver built from `AppStore`, and enforces name ownership on writes. A new `ecosystem partner` CLI manages credentials.

**Tech Stack:** Python 3, FastAPI, Starlette `TestClient`, pytest (`.venv/bin/python -m pytest`), stdlib `json`/`secrets`/`os`.

**Spec:** `docs/superpowers/specs/2026-07-10-per-app-auth-enrollment-design.md`

## Global Constraints

- Run tests: `.venv/bin/python -m pytest tests/<file> -v` from the appEcosystem repo root.
- **CLI naming deviation (spec said `ecosystem apps`):** `apps` is already taken (lists device apps, `cli/commands.py:cmd_apps`). Use **`ecosystem partner`** for credential management. Everything else matches the spec.
- **Backward compatibility is non-negotiable:** a request with **no** `X-Ecosystem-Key-Id` header MUST verify against the shared secret exactly as today and yield the owner principal. `sign_request(...)` with no `key_id` MUST return byte-identical headers to today. Existing tests + `scripts/smoke-ecosystem.sh` MUST stay green.
- **Fail closed:** unknown/suspended key → 401; unowned name → 403; reserved name by non-owner → 403; corrupt/missing `apps.json` → empty store (owner still works), never a crash.
- **Never log secrets** (per-app or shared). CLI prints a credential exactly once on `partner add`.
- Header value: `KEY_ID_HEADER = "X-Ecosystem-Key-Id"`.
- Reserved names: `{"registry", "openeye", "aegissiem", "aegissiem_daemon", "ai_for_survival", "magicmirror"}`.
- Owner principal shape: `{"auth_method": "hmac", "app_id": "__owner__", "scopes": ["*"], "owned_names": ["*"], "payload": <body dict>}`.
- Per-app principal shape (returned by `authenticate_request`): `{"auth_method": "hmac", "app_id": <str>, "scopes": [<str>...], "owned_names": [<str>...], "payload": <body dict>}` — **never** includes the secret.

## File Structure

| File | Responsibility |
|------|----------------|
| Modify `auth/python/ecosystem_auth/tokens.py` | `KEY_ID_HEADER` const; `sign_request(..., key_id=None)` |
| Modify `auth/python/ecosystem_auth/middleware.py` | `authenticate_request()` helper w/ `key_resolver`; `require_ecosystem_auth` delegates |
| Create `registry/app_store.py` | `AppStore` (JSON + mtime reload), `RESERVED_NAMES`, `default_apps_path()` |
| Modify `registry/app.py` | build `AppStore` in lifespan; `require_registry_auth` dep; `require_name_owner`; enforce on `/register`, `/deregister`, `/ai-profile` |
| Modify `cli/commands.py` + `cli/main.py` | `ecosystem partner add/list/show/suspend/resume/remove` |
| Create `tests/test_app_store.py` | AppStore unit tests |
| Modify `tests/test_auth.py` (or new `tests/test_middleware_keyid.py`) | resolver + back-compat tests |
| Create `tests/test_registry_partner_auth.py` | route enforcement via TestClient |
| Modify `tests/test_cli.py` | partner CLI tests |
| Modify `ECOSYSTEM_OPENING_PLAN.md` | tick Phase 1; keep Phase 1.5/2/3 follow-ups |

---

### Task 1: `KEY_ID_HEADER` + `sign_request(key_id=...)`

**Files:**
- Modify: `auth/python/ecosystem_auth/tokens.py` (header consts ~line 180-182; `sign_request` ~185-205)
- Test: `tests/test_auth.py` (append)

**Interfaces:**
- Consumes: existing `sign_request(method, url, secret, body=None, ts=None, nonce=None) -> dict`, `SIGNATURE_HEADER/TIMESTAMP_HEADER/NONCE_HEADER`.
- Produces: `KEY_ID_HEADER = "X-Ecosystem-Key-Id"`; `sign_request(..., key_id: str | None = None)` — adds the key-id header only when `key_id` is truthy. Later tasks import `KEY_ID_HEADER` and pass `key_id=`.

- [ ] **Step 1: Write the failing test** (append to `tests/test_auth.py`)

```python
def test_sign_request_without_key_id_omits_header():
    from ecosystem_auth.tokens import sign_request, KEY_ID_HEADER
    headers = sign_request("POST", "http://x/register", "s3cr3t", {"name": "a"})
    assert KEY_ID_HEADER not in headers

def test_sign_request_with_key_id_adds_header():
    from ecosystem_auth.tokens import sign_request, KEY_ID_HEADER
    headers = sign_request("POST", "http://x/register", "s3cr3t", {"name": "a"}, key_id="k_123")
    assert headers[KEY_ID_HEADER] == "k_123"

def test_sign_request_key_id_does_not_change_signature():
    from ecosystem_auth.tokens import sign_request, SIGNATURE_HEADER
    kw = dict(ts=1000, nonce="fixednonce")
    a = sign_request("POST", "http://x/register", "s3cr3t", {"name": "a"}, **kw)
    b = sign_request("POST", "http://x/register", "s3cr3t", {"name": "a"}, key_id="k_123", **kw)
    assert a[SIGNATURE_HEADER] == b[SIGNATURE_HEADER]  # key_id is not part of the signed payload
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_auth.py -k key_id -v`
Expected: FAIL — `ImportError: cannot import name 'KEY_ID_HEADER'`.

- [ ] **Step 3: Implement**

In `auth/python/ecosystem_auth/tokens.py`, after the existing header constants (near line 182) add:

```python
KEY_ID_HEADER = "X-Ecosystem-Key-Id"
```

Change `sign_request` to accept and attach `key_id` (do NOT add it to the signed payload):

```python
def sign_request(
    method: str,
    url: str,
    secret: str,
    body: Optional[dict] = None,
    ts: Optional[int] = None,
    nonce: Optional[str] = None,
    key_id: Optional[str] = None,
) -> dict:
    """Produce signature/timestamp/nonce headers for an authenticated request.

    The signed payload binds method, canonical path, a timestamp and a unique
    nonce, plus a digest of the body, so captured requests cannot be replayed.
    ``key_id`` (optional) is attached as a header to identify a per-app
    credential; it is NOT part of the signed payload.
    """
    ts = int(time.time()) if ts is None else ts
    nonce = nonce or secrets.token_hex(16)
    payload = _request_payload(method, url, ts, nonce, body)
    headers = {
        SIGNATURE_HEADER: sign_payload(payload, secret),
        TIMESTAMP_HEADER: str(ts),
        NONCE_HEADER: nonce,
    }
    if key_id:
        headers[KEY_ID_HEADER] = key_id
    return headers
```

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_auth.py -k key_id -v`
Expected: 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add auth/python/ecosystem_auth/tokens.py tests/test_auth.py
git commit -m "feat(auth): X-Ecosystem-Key-Id header + optional key_id in sign_request"
```

---

### Task 2: `authenticate_request` helper + per-app resolver path

**Files:**
- Modify: `auth/python/ecosystem_auth/middleware.py` (whole file)
- Test: create `tests/test_middleware_keyid.py`

**Interfaces:**
- Consumes: `KEY_ID_HEADER` (Task 1); existing `verify_request`, `get_ecosystem_secret`, `_nonce_store`, `verify_ecosystem_token`.
- Produces:
  - `authenticate_request(request, credentials, key_resolver=None) -> dict` — plain async helper (NOT a FastAPI dependency). `key_resolver: Callable[[str], dict | None]`. Returns the owner or per-app principal shape from Global Constraints. Raises `HTTPException` on failure.
  - `require_ecosystem_auth(request, credentials=Depends(security_scheme)) -> dict` — unchanged signature; delegates to `authenticate_request(..., key_resolver=None)`.
  - Resolver contract: given a `key_id`, returns a dict with keys `secret`, `app_id`, `scopes`, `owned_names` for an active app, or `None` for unknown/suspended. Task 4 supplies the registry resolver.

- [ ] **Step 1: Write the failing tests** (`tests/test_middleware_keyid.py`, new)

```python
"""Per-app key resolver path in ecosystem_auth.middleware."""
import json
import pytest
from starlette.requests import Request

from ecosystem_auth import middleware
from ecosystem_auth.tokens import sign_request, KEY_ID_HEADER


def _asgi_request(method, url, headers: dict, body: bytes = b""):
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    scope = {
        "type": "http", "method": method, "headers": raw,
        "path": "/register", "query_string": b"",
        "server": ("testserver", 80), "scheme": "http",
    }
    # provide the URL host/path Starlette needs to reconstruct str(request.url)
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    scope["path"] = parts.path
    scope["server"] = (parts.hostname or "testserver", parts.port or 80)
    scope["scheme"] = parts.scheme or "http"

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}
    return Request(scope, receive)


@pytest.fixture(autouse=True)
def _reset_nonce():
    middleware._nonce_store._seen.clear()
    yield
    middleware._nonce_store._seen.clear()


@pytest.mark.asyncio
async def test_absent_key_id_uses_shared_secret_owner(monkeypatch):
    monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", "shared-secret-value-123")
    url = "http://testserver/register"
    body = {"name": "openeye"}
    raw = json.dumps(body).encode()
    headers = sign_request("POST", url, "shared-secret-value-123", body)
    req = _asgi_request("POST", url, headers, raw)
    principal = await middleware.authenticate_request(req, None, key_resolver=None)
    assert principal["app_id"] == "__owner__"
    assert principal["owned_names"] == ["*"]


@pytest.mark.asyncio
async def test_valid_key_id_returns_app_principal(monkeypatch):
    monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", "shared-secret-value-123")
    app_secret = "app-secret-abc"
    url = "http://testserver/register"
    body = {"name": "acme_thermostat"}
    raw = json.dumps(body).encode()
    headers = sign_request("POST", url, app_secret, body, key_id="k_acme")

    def resolver(key_id):
        assert key_id == "k_acme"
        return {"secret": app_secret, "app_id": "org.acme", "scopes": ["register:self"],
                "owned_names": ["acme_thermostat"]}

    req = _asgi_request("POST", url, headers, raw)
    principal = await middleware.authenticate_request(req, None, key_resolver=resolver)
    assert principal["app_id"] == "org.acme"
    assert principal["owned_names"] == ["acme_thermostat"]
    assert "secret" not in principal


@pytest.mark.asyncio
async def test_unknown_or_suspended_key_id_401(monkeypatch):
    monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", "shared-secret-value-123")
    url = "http://testserver/register"
    body = {"name": "x"}
    headers = sign_request("POST", url, "whatever", body, key_id="k_missing")
    req = _asgi_request("POST", url, headers, json.dumps(body).encode())
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        await middleware.authenticate_request(req, None, key_resolver=lambda k: None)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_wrong_secret_under_valid_key_id_401(monkeypatch):
    monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", "shared-secret-value-123")
    url = "http://testserver/register"
    body = {"name": "acme_thermostat"}
    # sign with the WRONG secret but a valid key_id
    headers = sign_request("POST", url, "wrong-secret", body, key_id="k_acme")
    req = _asgi_request("POST", url, headers, json.dumps(body).encode())
    from fastapi import HTTPException
    resolver = lambda k: {"secret": "the-real-secret", "app_id": "org.acme",
                          "scopes": [], "owned_names": ["acme_thermostat"]}
    with pytest.raises(HTTPException) as exc:
        await middleware.authenticate_request(req, None, key_resolver=resolver)
    assert exc.value.status_code == 401
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_middleware_keyid.py -v`
Expected: FAIL — `AttributeError: module 'ecosystem_auth.middleware' has no attribute 'authenticate_request'`.

- [ ] **Step 3: Implement** — replace the body of `auth/python/ecosystem_auth/middleware.py` with:

```python
"""FastAPI middleware/dependency for ecosystem authentication."""

import json
from typing import Callable, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .tokens import (
    KEY_ID_HEADER,
    NONCE_HEADER,
    NonceStore,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    get_ecosystem_secret,
    verify_request,
)

security_scheme = HTTPBearer(auto_error=False)

# Process-wide nonce cache for replay detection on the signature path.
_nonce_store = NonceStore()


async def _read_body_obj(request: Request) -> dict:
    raw = await request.body()
    if request.method in ("GET", "DELETE") or not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON body"
        )


async def authenticate_request(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials],
    key_resolver: Optional[Callable[[str], Optional[dict]]] = None,
) -> dict:
    """Verify an ecosystem-authenticated request and return its principal.

    Per-app path: when an ``X-Ecosystem-Key-Id`` header is present AND a
    ``key_resolver`` is supplied, resolve the app, verify the HMAC against the
    app's secret, and return that app's principal. Owner path: otherwise verify
    against the shared secret and return the ``__owner__`` principal. Bearer
    tokens are accepted as before. Raises ``HTTPException`` on any failure.
    """
    signature = request.headers.get(SIGNATURE_HEADER)
    if signature:
        timestamp = request.headers.get(TIMESTAMP_HEADER)
        nonce = request.headers.get(NONCE_HEADER)
        body_obj = await _read_body_obj(request)

        key_id = request.headers.get(KEY_ID_HEADER)
        if key_id and key_resolver is not None:
            principal = key_resolver(key_id)
            if not principal:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Unknown or suspended ecosystem key",
                )
            secret = principal["secret"]
            if not verify_request(
                request.method, str(request.url), secret, signature,
                timestamp, nonce, body_obj, nonce_store=_nonce_store,
            ):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid, stale, or replayed ecosystem signature",
                )
            return {
                "auth_method": "hmac",
                "app_id": principal["app_id"],
                "scopes": list(principal.get("scopes", [])),
                "owned_names": list(principal.get("owned_names", [])),
                "payload": body_obj,
            }

        # Owner path: shared secret.
        secret = get_ecosystem_secret()
        if not verify_request(
            request.method, str(request.url), secret, signature,
            timestamp, nonce, body_obj, nonce_store=_nonce_store,
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid, stale, or replayed ecosystem signature",
            )
        return {
            "auth_method": "hmac",
            "app_id": "__owner__",
            "scopes": ["*"],
            "owned_names": ["*"],
            "payload": body_obj,
        }

    if credentials:
        from .tokens import verify_ecosystem_token

        try:
            token_data = json.loads(credentials.credentials)
        except (json.JSONDecodeError, TypeError):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format"
            )
        if not verify_ecosystem_token(token_data, get_ecosystem_secret()):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired ecosystem token",
            )
        return {"auth_method": "token", "service": token_data.get("service")}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing ecosystem authentication",
    )


async def require_ecosystem_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> dict:
    """FastAPI dependency: validate an ecosystem-authenticated request (shared-secret/owner)."""
    return await authenticate_request(request, credentials, key_resolver=None)
```

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_middleware_keyid.py -v`
Expected: 4 PASS. Then back-compat: `.venv/bin/python -m pytest tests/test_registry_app.py tests/test_registry_security.py -v` → all PASS (owner path unchanged).

- [ ] **Step 5: Commit**

```bash
git add auth/python/ecosystem_auth/middleware.py tests/test_middleware_keyid.py
git commit -m "feat(auth): authenticate_request helper with per-app key resolver path"
```

---

### Task 3: `AppStore` (credential store with live reload)

**Files:**
- Create: `registry/app_store.py`
- Test: create `tests/test_app_store.py`

**Interfaces:**
- Produces:
  - `RESERVED_NAMES: set[str]` (exact set from Global Constraints).
  - `default_apps_path() -> str` — `ECOSYSTEM_APPS_FILE` env or `~/.config/ecosystem/apps.json`.
  - `class AppStore(persistence_path: str | None = None)` with:
    - `add(app_id, display_name, owner, owned_names, scopes=None) -> tuple[dict, str]` — returns (record-without-secret, raw_secret). status `"approved"`. Raises `ValueError` if `app_id` exists, or any name in `owned_names` is reserved or already owned by another app.
    - `get(app_id) -> dict | None` (record without secret)
    - `get_by_key_id(key_id) -> dict | None` (**full** record incl. `secret`, only if status `"approved"`)
    - `list() -> list[dict]` (records without secrets)
    - `set_status(app_id, status) -> bool`; `remove(app_id) -> bool`
    - `all_owned_names() -> set[str]`
  - Task 4 uses `get_by_key_id`; Task 5 uses `add/list/get/set_status/remove/all_owned_names` and `RESERVED_NAMES`.

- [ ] **Step 1: Write the failing tests** (`tests/test_app_store.py`)

```python
import os
import stat
import pytest
from registry.app_store import AppStore, RESERVED_NAMES, default_apps_path


@pytest.fixture
def store(tmp_path):
    return AppStore(persistence_path=str(tmp_path / "apps.json"))


def test_add_returns_secret_once_and_persists(store, tmp_path):
    rec, secret = store.add("org.acme", "Acme", "dev@acme", ["acme_thermostat"])
    assert rec["app_id"] == "org.acme"
    assert rec["status"] == "approved"
    assert "secret" not in rec           # list/get views never expose the secret
    assert secret and len(secret) >= 20
    assert (tmp_path / "apps.json").exists()


def test_get_by_key_id_returns_full_record_with_secret(store):
    rec, secret = store.add("org.acme", "Acme", "dev@acme", ["acme_thermostat"])
    full = store.get_by_key_id(rec["key_id"])
    assert full["secret"] == secret
    assert full["app_id"] == "org.acme"


def test_get_by_key_id_unknown_returns_none(store):
    assert store.get_by_key_id("nope") is None


def test_suspended_app_not_resolvable_by_key_id(store):
    rec, _ = store.add("org.acme", "Acme", "dev@acme", ["acme_thermostat"])
    store.set_status("org.acme", "suspended")
    assert store.get_by_key_id(rec["key_id"]) is None


def test_add_rejects_reserved_name(store):
    with pytest.raises(ValueError):
        store.add("org.evil", "Evil", "e@x", ["openeye"])


def test_add_rejects_duplicate_owned_name(store):
    store.add("org.a", "A", "a@x", ["shared_name"])
    with pytest.raises(ValueError):
        store.add("org.b", "B", "b@x", ["shared_name"])


def test_add_rejects_duplicate_app_id(store):
    store.add("org.a", "A", "a@x", ["name_a"])
    with pytest.raises(ValueError):
        store.add("org.a", "A2", "a@x", ["name_a2"])


def test_file_is_chmod_600(store, tmp_path):
    store.add("org.acme", "Acme", "dev@acme", ["acme_thermostat"])
    mode = stat.S_IMODE(os.stat(tmp_path / "apps.json").st_mode)
    assert mode == 0o600


def test_live_reload_on_external_change(tmp_path):
    path = str(tmp_path / "apps.json")
    a = AppStore(persistence_path=path)
    rec, _ = a.add("org.acme", "Acme", "dev@acme", ["acme_thermostat"])
    # a second store (simulating the CLI process) suspends the app
    b = AppStore(persistence_path=path)
    b.set_status("org.acme", "suspended")
    # the first store must observe the change on next lookup (mtime reload)
    assert a.get_by_key_id(rec["key_id"]) is None


def test_corrupt_file_yields_empty_store(tmp_path):
    path = tmp_path / "apps.json"
    path.write_text("{ not json")
    a = AppStore(persistence_path=str(path))
    assert a.list() == []


def test_remove(store):
    store.add("org.acme", "Acme", "dev@acme", ["acme_thermostat"])
    assert store.remove("org.acme") is True
    assert store.get("org.acme") is None
    assert store.remove("org.acme") is False


def test_default_path_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("ECOSYSTEM_APPS_FILE", str(tmp_path / "custom.json"))
    assert default_apps_path() == str(tmp_path / "custom.json")
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_app_store.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'registry.app_store'`.

- [ ] **Step 3: Implement** (`registry/app_store.py`)

```python
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
```

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_app_store.py -v`
Expected: all PASS (12 tests).

- [ ] **Step 5: Commit**

```bash
git add registry/app_store.py tests/test_app_store.py
git commit -m "feat(registry): AppStore per-app credential store with live reload"
```

---

### Task 4: Registry wiring — resolver dependency, name-ownership enforcement

**Files:**
- Modify: `registry/app.py` (lifespan ~28-67; `require_read_auth` ~122-129; routes at ~196 `/ai-profile`, ~228 `/register`, ~239 `/deregister`)
- Test: create `tests/test_registry_partner_auth.py`

**Interfaces:**
- Consumes: `AppStore`, `RESERVED_NAMES` (Task 3); `authenticate_request` (Task 2); `sign_request`, `KEY_ID_HEADER` (Task 1).
- Produces: `require_registry_auth` dependency and `require_name_owner(name, auth)` helper used on the three write routes; `app.state.app_store`.

- [ ] **Step 1: Write the failing tests** (`tests/test_registry_partner_auth.py`)

```python
import json
import pytest
from fastapi.testclient import TestClient

from registry.app import app
from registry.app_store import AppStore
from ecosystem_auth.tokens import sign_request

OWNER_SECRET = "owner-shared-secret-value"


@pytest.fixture
def env(tmp_path, monkeypatch):
    apps_file = tmp_path / "apps.json"
    monkeypatch.setenv("ECOSYSTEM_REGISTRY_FILE", str(tmp_path / "registry.json"))
    monkeypatch.setenv("ECOSYSTEM_CONFIG", str(tmp_path / "missing.yaml"))
    monkeypatch.setenv("ECOSYSTEM_AI_PROFILE_FILE", str(tmp_path / "ai_profile.json"))
    monkeypatch.setenv("ECOSYSTEM_APPS_FILE", str(apps_file))
    monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", OWNER_SECRET)
    from ecosystem_auth import middleware
    middleware._nonce_store._seen.clear()
    # provision one third-party app via a store pointed at the same file
    store = AppStore(persistence_path=str(apps_file))
    rec, secret = store.add("org.acme", "Acme", "dev@acme", ["acme_thermostat"])
    return {"apps_file": str(apps_file), "key_id": rec["key_id"], "secret": secret, "store": store}


def _post_register(client, name, secret, key_id=None):
    url = "http://testserver/register"
    body = {"name": name, "port": 9000, "host": "localhost"}
    headers = sign_request("POST", url, secret, body, key_id=key_id)
    return client.post("/register", json=body, headers=headers)


def test_partner_registers_its_owned_name(env):
    with TestClient(app) as client:
        r = _post_register(client, "acme_thermostat", env["secret"], env["key_id"])
        assert r.status_code == 201


def test_partner_cannot_register_foreign_name(env):
    with TestClient(app) as client:
        r = _post_register(client, "someone_else", env["secret"], env["key_id"])
        assert r.status_code == 403


def test_partner_cannot_register_reserved_name(env):
    with TestClient(app) as client:
        r = _post_register(client, "openeye", env["secret"], env["key_id"])
        assert r.status_code == 403


def test_owner_can_register_any_name(env):
    with TestClient(app) as client:
        r = _post_register(client, "openeye", OWNER_SECRET)  # no key_id -> owner
        assert r.status_code == 201


def test_suspended_partner_gets_401(env):
    env["store"].set_status("org.acme", "suspended")
    with TestClient(app) as client:
        r = _post_register(client, "acme_thermostat", env["secret"], env["key_id"])
        assert r.status_code == 401


def test_partner_cannot_write_ai_profile(env):
    with TestClient(app) as client:
        url = "http://testserver/ai-profile"
        body = {"selected_model": "evil"}
        headers = sign_request("PUT", url, env["secret"], body, key_id=env["key_id"])
        r = client.put("/ai-profile", json=body, headers=headers)
        assert r.status_code == 403


def test_owner_can_write_ai_profile(env):
    with TestClient(app) as client:
        url = "http://testserver/ai-profile"
        body = {"selected_model": "llama3"}
        headers = sign_request("PUT", url, OWNER_SECRET, body)
        r = client.put("/ai-profile", json=body, headers=headers)
        assert r.status_code == 200


def test_partner_deregister_foreign_name_403(env):
    with TestClient(app) as client:
        _post_register(client, "acme_thermostat", env["secret"], env["key_id"])
        url = "http://testserver/deregister/openeye"
        headers = sign_request("DELETE", url, env["secret"], None, key_id=env["key_id"])
        r = client.delete("/deregister/openeye", headers=headers)
        assert r.status_code == 403
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_registry_partner_auth.py -v`
Expected: FAIL — partner registrations currently succeed (200/201) or error because enforcement/`app_store` don't exist yet.

- [ ] **Step 3: Implement** in `registry/app.py`.

(a) Imports near the top (with the other `from ecosystem_auth...` / `from .` imports):

```python
from ecosystem_auth.middleware import authenticate_request, require_ecosystem_auth, security_scheme
from .app_store import AppStore, RESERVED_NAMES, default_apps_path
```
(Keep the existing `require_ecosystem_auth, security_scheme` import — just add `authenticate_request`.)

(b) In `lifespan`, after `ai_profile_store = AIProfileStore(...)` and alongside the other `app.state.*` assignments (~line 60-67), add:

```python
    app_store = AppStore(persistence_path=os.environ.get("ECOSYSTEM_APPS_FILE") or default_apps_path())
    app.state.app_store = app_store
```

(c) Add the resolver + registry auth dependency + ownership helper (place after `require_read_auth`, ~line 130):

```python
def _key_resolver(request: Request):
    store = getattr(request.app.state, "app_store", None)
    if store is None:
        return None
    def resolve(key_id: str):
        return store.get_by_key_id(key_id)  # None if unknown/suspended
    return resolve


async def require_registry_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> dict:
    """Registry auth: per-app key when present, else shared-secret owner."""
    return await authenticate_request(request, credentials, key_resolver=_key_resolver(request))


def require_name_owner(name: str, auth: dict) -> None:
    """403 unless the caller owns `name` (owner may use any non-collision name)."""
    owned = auth.get("owned_names", [])
    if owned == ["*"]:
        return
    if name in RESERVED_NAMES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"'{name}' is a reserved first-party service name",
        )
    if name not in owned:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"app '{auth.get('app_id')}' does not own service name '{name}'",
        )
```

(d) Update `require_read_auth` to route through the resolver-aware path (so an enrolled app can read when read-auth is enabled):

```python
async def require_read_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
):
    if not _read_auth_required():
        return None
    return await require_registry_auth(request, credentials)
```

(e) `POST /register` — swap the dependency and enforce ownership:

```python
@app.post("/register", response_model=ServiceRecord, status_code=status.HTTP_201_CREATED)
async def register_service(
    registration: ServiceRegistration,
    auth: dict = Depends(require_registry_auth),
    registry: ServiceRegistry = Depends(get_registry),
):
    """Register a new service with the ecosystem."""
    require_name_owner(registration.name, auth)
    record = registry.register(registration)
    return record
```

(f) `DELETE /deregister/{name}`:

```python
@app.delete("/deregister/{name}")
async def deregister_service(
    name: str,
    auth: dict = Depends(require_registry_auth),
    registry: ServiceRegistry = Depends(get_registry),
):
    """Remove a service from the registry."""
    require_name_owner(name, auth)
    if not registry.deregister(name):
        raise HTTPException(status_code=404, detail=f"Service '{name}' not found")
    return {"status": "deregistered", "name": name}
```

(g) `PUT /ai-profile` — owner-only + real `updated_by`:

```python
@app.put("/ai-profile")
async def update_ai_profile(
    changes: dict,
    request: Request,
    auth: dict = Depends(require_registry_auth),
    store=Depends(get_profile_store),
):
    if auth.get("app_id") != "__owner__":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="AI profile changes are owner-only",
        )
    updated_by = auth.get("app_id") or "unknown"
    profile = store.update(changes, updated_by=updated_by)
    # ... (leave the existing event_bus.publish block below unchanged) ...
```

Ensure `Optional`, `Request`, `HTTPAuthorizationCredentials`, `Depends`, `status`, `HTTPException` are already imported at the top of `app.py` (they are used elsewhere in the file — add any that aren't).

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_registry_partner_auth.py -v`
Expected: 8 PASS. Back-compat: `.venv/bin/python -m pytest tests/test_registry_app.py tests/test_registry_security.py tests/test_middleware_keyid.py tests/test_app_store.py -v` → all PASS.

- [ ] **Step 5: Commit**

```bash
git add registry/app.py tests/test_registry_partner_auth.py
git commit -m "feat(registry): per-app auth resolver + name-ownership enforcement on writes"
```

---

### Task 5: `ecosystem partner` CLI

**Files:**
- Modify: `cli/commands.py` (add `cmd_partner`), `cli/main.py` (subparser + dispatch)
- Test: `tests/test_cli.py` (append)

**Interfaces:**
- Consumes: `AppStore`, `RESERVED_NAMES` (Task 3).
- Produces: `cmd_partner(action, app_id=None, name=None, owner=None, service_names=None) -> int`; `ecosystem partner add|list|show|suspend|resume|remove`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_cli.py`)

```python
def test_partner_add_and_list(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("ECOSYSTEM_APPS_FILE", str(tmp_path / "apps.json"))
    from cli.commands import cmd_partner
    rc = cmd_partner("add", app_id="org.acme", name="Acme", owner="dev@acme",
                     service_names="acme_thermostat")
    assert rc == 0
    out = capsys.readouterr().out
    assert "org.acme" in out and "key_id" in out.lower() and "secret" in out.lower()

    rc = cmd_partner("list")
    assert rc == 0
    out = capsys.readouterr().out
    assert "org.acme" in out and "acme_thermostat" in out


def test_partner_add_rejects_reserved_name(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("ECOSYSTEM_APPS_FILE", str(tmp_path / "apps.json"))
    from cli.commands import cmd_partner
    rc = cmd_partner("add", app_id="org.evil", name="Evil", owner="e@x",
                     service_names="openeye")
    assert rc == 1
    assert "reserved" in capsys.readouterr().out.lower()


def test_partner_list_and_show_never_print_secret(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("ECOSYSTEM_APPS_FILE", str(tmp_path / "apps.json"))
    from cli.commands import cmd_partner
    cmd_partner("add", app_id="org.acme", name="Acme", owner="dev@acme",
                service_names="acme_thermostat")
    secret_line = [l for l in capsys.readouterr().out.splitlines() if "secret" in l.lower()]
    printed_secret = secret_line[0].split()[-1] if secret_line else "UNSET"
    cmd_partner("show", app_id="org.acme")
    cmd_partner("list")
    out = capsys.readouterr().out
    assert printed_secret not in out  # secret shown only once at add time


def test_partner_suspend(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("ECOSYSTEM_APPS_FILE", str(tmp_path / "apps.json"))
    from cli.commands import cmd_partner
    cmd_partner("add", app_id="org.acme", name="Acme", owner="dev@acme",
                service_names="acme_thermostat")
    capsys.readouterr()
    rc = cmd_partner("suspend", app_id="org.acme")
    assert rc == 0
    cmd_partner("show", app_id="org.acme")
    assert "suspended" in capsys.readouterr().out.lower()
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_cli.py -k partner -v`
Expected: FAIL — `ImportError: cannot import name 'cmd_partner'`.

- [ ] **Step 3: Implement** — add to `cli/commands.py`:

```python
def cmd_partner(action: str, app_id: str | None = None, name: str | None = None,
                owner: str | None = None, service_names: str | None = None) -> int:
    """Manage third-party partner app credentials (per-app HMAC keys)."""
    from registry.app_store import AppStore
    store = AppStore()

    if action == "add":
        if not (app_id and name and owner and service_names):
            print("Usage: ecosystem partner add <app_id> --name <display> "
                  "--owner <contact> --service-names a,b")
            return 1
        names = [n.strip() for n in service_names.split(",") if n.strip()]
        try:
            rec, secret = store.add(app_id, name, owner, names)
        except ValueError as e:
            print(f"Error: {e}")
            return 1
        print(f"Created partner app '{rec['app_id']}' (owns: {', '.join(rec['owned_names'])})")
        print("Copy these now — the secret is shown only once:")
        print(f"  key_id: {rec['key_id']}")
        print(f"  secret: {secret}")
        return 0

    if action == "list":
        apps = store.list()
        if not apps:
            print("No partner apps registered.")
            return 0
        print(f"Partner apps ({len(apps)}):\n")
        for a in apps:
            print(f"  {a['status']:<9} {a['app_id']:<24} {a['display_name']:<18} "
                  f"owns={','.join(a['owned_names'])}  created={a['created_at']}")
        return 0

    if action == "show":
        if not app_id:
            print("Usage: ecosystem partner show <app_id>")
            return 1
        a = store.get(app_id)
        if not a:
            print(f"No such partner app: {app_id}")
            return 1
        for k in ("app_id", "key_id", "display_name", "owner", "owned_names",
                  "scopes", "status", "created_at"):
            print(f"  {k}: {a.get(k)}")
        return 0

    if action in ("suspend", "resume", "remove"):
        if not app_id:
            print(f"Usage: ecosystem partner {action} <app_id>")
            return 1
        if action == "remove":
            ok = store.remove(app_id)
        else:
            ok = store.set_status(app_id, "suspended" if action == "suspend" else "approved")
        if not ok:
            print(f"No such partner app: {app_id}")
            return 1
        print(f"Partner app '{app_id}' {action}d." if action != "remove"
              else f"Partner app '{app_id}' removed.")
        return 0

    print(f"Unknown partner action: {action} (use add|list|show|suspend|resume|remove)")
    return 1
```

Wire it in `cli/main.py`: add `cmd_partner` to the import from `.commands`; add the subparser after the `secret` parser (~line 49):

```python
    partner_parser = sub.add_parser("partner", help="Manage third-party partner app credentials")
    partner_parser.add_argument(
        "action", choices=["add", "list", "show", "suspend", "resume", "remove"])
    partner_parser.add_argument("app_id", nargs="?", default=None)
    partner_parser.add_argument("--name", default=None, help="Display name (add)")
    partner_parser.add_argument("--owner", default=None, help="Owner contact (add)")
    partner_parser.add_argument("--service-names", dest="service_names", default=None,
                                help="Comma-separated service names the app may manage (add)")
```

and dispatch (after the `apps` branch, ~line 71):

```python
    elif args.command == "partner":
        sys.exit(cmd_partner(args.action, args.app_id, args.name, args.owner, args.service_names))
```

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_cli.py -k partner -v`
Expected: 4 PASS. Then `.venv/bin/python -m pytest tests/test_cli.py -v` (no regressions).

- [ ] **Step 5: Commit**

```bash
git add cli/commands.py cli/main.py tests/test_cli.py
git commit -m "feat(cli): ecosystem partner add/list/show/suspend/resume/remove"
```

---

### Task 6: Full suite, smoke test, docs + follow-ups

**Files:**
- Modify: `ECOSYSTEM_OPENING_PLAN.md`
- Verify only: `scripts/smoke-ecosystem.sh`

- [ ] **Step 1: Full test suite**

Run: `.venv/bin/python -m pytest tests/ -v`
Expected: all green, or any failures identical to a pre-change baseline. Investigate/report any NEW failure — do not paper over.

- [ ] **Step 2: Back-compat smoke test**

Run: `bash scripts/smoke-ecosystem.sh`
Expected: `SMOKE TEST PASSED` (the existing single-secret flow is unchanged).

- [ ] **Step 3: Update `ECOSYSTEM_OPENING_PLAN.md`**

Under Part B, mark Phase 1 delivered (per-app HMAC keys, owner-CLI provisioning via `ecosystem partner`, name ownership, reserved names, suspend/revoke). Confirm the following remain as **open follow-ups** (verbatim intent preserved):
- **Phase 1.5:** migrate first-party apps (openeye, aegissiem, aegissiem_daemon, ai_for_survival, magicmirror) to their own per-app keys and retire the grandfathered shared-secret owner for day-to-day writes, once the flow is proven.
- **Phase 2:** self-service `POST /enroll` + one-time invite tokens + `pending→approved` state; scopes beyond `register:self`; topic-scoped event publishing; per-app rate limits; SSRF fix on health polling; write audit log; admin page.
- **Phase 3:** asymmetric keys (Ed25519; registry stores only public keys); app catalog.

- [ ] **Step 4: Commit**

```bash
git add ECOSYSTEM_OPENING_PLAN.md
git commit -m "docs: mark Phase 1 (per-app auth) delivered; keep Phase 1.5/2/3 follow-ups"
```

---

## Self-review notes

- **Spec coverage:** AppStore (T3), auth resolver + back-compat (T1,T2), name ownership + ai-profile owner-only (T4), CLI (T5), tests throughout, docs/follow-ups (T6). All spec success criteria mapped.
- **Deviations from spec (intentional):** (1) CLI command is `ecosystem partner`, not `ecosystem apps` — `apps` is taken by the device-apps command. (2) Added mtime-based live reload to `AppStore` — required to satisfy spec success-criterion 3 ("suspend revokes immediately") without a registry restart, which the spec implied but didn't detail. (3) Refactored middleware into `authenticate_request` + thin `require_ecosystem_auth` — required because adding `key_resolver` to the dependency signature would make FastAPI treat it as a request parameter.
- **Back-compat guardrails:** `sign_request` without `key_id` byte-identical (T1 test); owner path unchanged (T2 test + existing registry tests re-run in T4); smoke test in T6.
- **Type consistency:** principal dict keys (`app_id`, `scopes`, `owned_names`, `payload`) identical across T2 (producer) and T4 (consumer); `owned_names == ["*"]` is the owner sentinel checked in `require_name_owner`.
