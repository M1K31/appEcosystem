# Ecosystem AI Providers & Cyber-Harness Integration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let users choose and manage cloud AI providers (Claude / Gemini / OpenAI) as an alternative to local Ollama models — with keys stored securely and manageable from each app's UI — and bring the cyber-harness daemon into the ecosystem as a bundled, opt-in service that cannot double-start or disturb local model selection.

**Architecture:** The shared `ecosystem_ai` package already implements the provider abstraction (`providers/{ollama,anthropic,openai,gemini}.py`, `ProviderRouter`, `build_router()`), and the registry already syncs an ecosystem-wide `AIProfile` via `GET/PUT /ai-profile`. Two things are missing: cloud provider API keys can only come from environment variables (`build_providers()` — "api_key resolved from env"), so users cannot manage them; and the harness daemon ignores all of it, calling Ollama directly. This plan adds a file-backed credential store behind authenticated registry endpoints, teaches `build_providers()` to read it, exposes management UI in each relevant app, and converts the harness daemon into a profile-driven, single-instance, opt-in service.

**Tech Stack:** Python 3.12 (harness/registry), Python 3.9 (OpenEye), FastAPI (registry, AFS, OpenEye), Flask+Jinja (AegisSIEM dashboard), React+TypeScript (AFS), React+JSX (OpenEye), aiohttp (harness daemon).

## Global Constraints

- **API keys are secrets.** They MUST never be returned by any read endpoint, never written to logs, never placed in `ai_profile.json`, and never included in an error message or exception string.
- A read endpoint returns only `{"configured": bool, "last4": str, "updated_at": str}` per provider. `last4` is the final 4 characters, or `""` when not configured.
- The credential file is `~/.config/ecosystem/provider_keys.json`, created with mode `0600` (override with `ECOSYSTEM_PROVIDER_KEYS_FILE`).
- Key **writes and deletes** require ecosystem auth **and** a loopback caller, 404-cloaked for non-loopback — mirroring the existing `/api/system/ecosystem/secret` precedent in AI-for-Survival.
- Key resolution order for every provider: explicit `api_key` argument → credential store → provider env var (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`/`GOOGLE_API_KEY`). This keeps existing env-var deployments working unchanged.
- **Local-first is preserved.** `default_provider` stays `"ollama"`. Nothing in this plan may change `selected_model`, `task_models`, or the hardware-tier model recommendation. Cloud is used only when a provider is explicitly `enabled` in the profile, or via `allow_cloud_fallback`.
- The harness daemon is **bundled but opt-in**: installed by the AegisSIEM/appEcosystem installers, started only when enabled. The registry must not advertise it while it is not serving.
- Exactly **one** harness daemon per machine. launchd is the sole owner; `ecosystem start-all` must not be a second start vector.
- Fixed port: harness daemon 8088, health `/api/status`.
- The implementer MUST NOT invent, generate, or enter real API keys. Tests use obvious fakes (`"sk-test-000000000000"`). Real keys are supplied by the user through the UI or CLI.
- Commit after each task.

---

### Task 1: File-backed provider credential store

**Files:**
- Create: `appEcosystem/registry/credential_store.py`
- Create: `appEcosystem/tests/test_credential_store.py`

**Interfaces:**
- Produces: `ProviderCredentialStore` with `set_key(provider, key)`, `get_key(provider) -> str | None`, `delete_key(provider) -> bool`, `status() -> dict[str, dict]`, and `SUPPORTED_PROVIDERS = ("anthropic", "openai", "gemini")`. Tasks 2, 3, and 4 all consume this class.

- [ ] **Step 1: Write the failing tests**

Create `appEcosystem/tests/test_credential_store.py`:

```python
"""Provider API-key store: persistence, masking, permissions."""
import json
import os
import stat

import pytest

from registry.credential_store import ProviderCredentialStore, SUPPORTED_PROVIDERS


@pytest.fixture
def store(tmp_path):
    return ProviderCredentialStore(path=str(tmp_path / "provider_keys.json"))


def test_set_and_get_roundtrip(store):
    store.set_key("anthropic", "sk-test-000000000000")
    assert store.get_key("anthropic") == "sk-test-000000000000"


def test_status_never_exposes_the_key(store):
    store.set_key("openai", "sk-test-000000001234")
    st = store.status()
    assert st["openai"]["configured"] is True
    assert st["openai"]["last4"] == "1234"
    assert "sk-test-000000001234" not in json.dumps(st)


def test_status_lists_all_supported_providers(store):
    st = store.status()
    assert set(st) == set(SUPPORTED_PROVIDERS)
    assert all(v["configured"] is False and v["last4"] == "" for v in st.values())


def test_delete_removes_the_key(store):
    store.set_key("gemini", "sk-test-000000000000")
    assert store.delete_key("gemini") is True
    assert store.get_key("gemini") is None
    assert store.delete_key("gemini") is False


def test_file_is_chmod_600(tmp_path):
    p = tmp_path / "provider_keys.json"
    ProviderCredentialStore(path=str(p)).set_key("anthropic", "sk-test-000000000000")
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


def test_rejects_unknown_provider(store):
    with pytest.raises(ValueError):
        store.set_key("hackerllm", "sk-test-000000000000")


def test_rejects_empty_key(store):
    with pytest.raises(ValueError):
        store.set_key("anthropic", "   ")


def test_missing_file_is_not_an_error(store):
    assert store.get_key("anthropic") is None
    assert store.status()["anthropic"]["configured"] is False
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd /Volumes/Locker2/GitHub/appEcosystem
~/.local/share/ecosystem/venv/bin/python -m pytest tests/test_credential_store.py -v
```
Expected: FAIL — `ModuleNotFoundError: No module named 'registry.credential_store'`

- [ ] **Step 3: Implement the store**

Create `appEcosystem/registry/credential_store.py`:

```python
"""File-backed storage for cloud AI provider API keys.

Keys live in ~/.config/ecosystem/provider_keys.json at mode 0600 — deliberately
NOT in ai_profile.json, which syncs across apps and is safe to read broadly.
Only `get_key` ever returns a secret; `status()` is the shape every API and UI
surfaces, and it exposes nothing beyond the last four characters.
"""
from __future__ import annotations

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
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        try:
            os.chmod(self._path, 0o600)
        except OSError:
            pass

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
        import datetime

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
```

- [ ] **Step 4: Run to verify it passes**

```bash
~/.local/share/ecosystem/venv/bin/python -m pytest tests/test_credential_store.py -v
```
Expected: 8 passed

- [ ] **Step 5: Commit**

```bash
git -C /Volumes/Locker2/GitHub/appEcosystem add registry/credential_store.py tests/test_credential_store.py
git -C /Volumes/Locker2/GitHub/appEcosystem commit -m "feat(registry): file-backed store for cloud provider API keys

Cloud providers could only take keys from environment variables, so users had no
way to enter or manage them. Adds a 0600 store at ~/.config/ecosystem/provider_keys.json
whose status() view exposes only configured/last4 — never the key itself."
```

---

### Task 2: Registry endpoints to manage provider keys

**Files:**
- Modify: `appEcosystem/registry/app.py` (wire the store into `app.state` near the `ai_profile_store` setup at ~line 62-74; add routes near the existing `/ai-profile` routes at ~line 220-250)
- Create: `appEcosystem/tests/test_provider_key_endpoints.py`

**Interfaces:**
- Consumes: `ProviderCredentialStore` from Task 1.
- Produces: `GET /ai/providers` → `{"providers": {<name>: {configured, last4, updated_at}}}`; `PUT /ai/providers/{provider}/key` body `{"api_key": "..."}` → `{"status": "stored", "provider": ..., "last4": ...}`; `DELETE /ai/providers/{provider}/key` → `{"status": "deleted"|"not_found"}`. Tasks 4, 8, 9, and 10 call these.

- [ ] **Step 1: Write the failing tests**

Create `appEcosystem/tests/test_provider_key_endpoints.py`:

```python
"""Provider-key endpoints: masking, authz, loopback gating."""
import pytest
from fastapi.testclient import TestClient

from registry.app import app
from registry.credential_store import ProviderCredentialStore


@pytest.fixture(autouse=True)
def _store(tmp_path, monkeypatch):
    monkeypatch.setenv("ECOSYSTEM_PROVIDER_KEYS_FILE", str(tmp_path / "keys.json"))
    store = ProviderCredentialStore(path=str(tmp_path / "keys.json"))
    app.state.provider_credential_store = store
    return store


@pytest.fixture
def client():
    return TestClient(app)


def test_get_lists_providers_without_keys(client, _store):
    _store.set_key("anthropic", "sk-test-000000009999")
    r = client.get("/ai/providers")
    assert r.status_code == 200
    body = r.json()["providers"]
    assert body["anthropic"]["configured"] is True
    assert body["anthropic"]["last4"] == "9999"
    assert "sk-test-000000009999" not in r.text


def test_put_stores_a_key(client, _store):
    r = client.put("/ai/providers/openai/key", json={"api_key": "sk-test-000000004321"})
    assert r.status_code == 200
    assert r.json()["last4"] == "4321"
    assert _store.get_key("openai") == "sk-test-000000004321"
    assert "sk-test-000000004321" not in r.text


def test_put_rejects_unknown_provider(client):
    r = client.put("/ai/providers/hackerllm/key", json={"api_key": "sk-test-000000000000"})
    assert r.status_code == 400


def test_put_rejects_empty_key(client):
    r = client.put("/ai/providers/openai/key", json={"api_key": "  "})
    assert r.status_code == 400


def test_delete_removes_a_key(client, _store):
    _store.set_key("gemini", "sk-test-000000000000")
    assert client.request("DELETE", "/ai/providers/gemini/key").json()["status"] == "deleted"
    assert _store.get_key("gemini") is None
    assert client.request("DELETE", "/ai/providers/gemini/key").json()["status"] == "not_found"


def test_writes_are_loopback_only(client):
    r = client.put(
        "/ai/providers/openai/key",
        json={"api_key": "sk-test-000000000000"},
        headers={"x-forwarded-for": "203.0.113.9"},
    )
    assert r.status_code == 404  # cloaked, not 403
```

- [ ] **Step 2: Run to verify it fails**

```bash
~/.local/share/ecosystem/venv/bin/python -m pytest tests/test_provider_key_endpoints.py -v
```
Expected: FAIL — 404s for the new routes.

- [ ] **Step 3: Wire the store into app state**

In `registry/app.py`, beside the `ai_profile_store` wiring (~line 62-74), add:

```python
from .credential_store import SUPPORTED_PROVIDERS, ProviderCredentialStore

provider_credential_store = ProviderCredentialStore()
app.state.provider_credential_store = provider_credential_store
```

- [ ] **Step 4: Add the routes**

In `registry/app.py`, next to the existing `/ai-profile` routes, add. Follow the existing route style for auth dependencies — use the same `require_ecosystem_auth` dependency the other mutating routes use:

```python
from fastapi import Body, HTTPException, Request
from pydantic import BaseModel


class ProviderKeyBody(BaseModel):
    api_key: str


def _provider_store(request: Request) -> ProviderCredentialStore:
    return request.app.state.provider_credential_store


def _require_loopback(request: Request) -> None:
    """Key writes are loopback-only, 404-cloaked (mirrors the secret endpoints).

    A forwarded header means the request crossed a proxy, so it is not a genuine
    local caller even when request.client.host looks local.
    """
    if request.headers.get("x-forwarded-for"):
        raise HTTPException(status_code=404, detail="Not Found")
    host = (request.client.host if request.client else "") or ""
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(status_code=404, detail="Not Found")


@app.get("/ai/providers")
async def list_provider_keys(request: Request):
    """Non-secret status for every supported provider. Never returns a key."""
    return {"providers": _provider_store(request).status()}


@app.put("/ai/providers/{provider}/key")
async def set_provider_key(provider: str, request: Request, body: ProviderKeyBody = Body(...)):
    _require_loopback(request)
    store = _provider_store(request)
    try:
        store.set_key(provider, body.api_key)
    except ValueError as e:
        # ValueError text is about the provider name or emptiness — never the key.
        raise HTTPException(status_code=400, detail=str(e))
    return {"status": "stored", "provider": provider, "last4": store.status()[provider]["last4"]}


@app.delete("/ai/providers/{provider}/key")
async def delete_provider_key(provider: str, request: Request):
    _require_loopback(request)
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unknown provider {provider!r}")
    removed = _provider_store(request).delete_key(provider)
    return {"status": "deleted" if removed else "not_found", "provider": provider}
```

If the registry's other mutating routes take an auth dependency (e.g. `Depends(require_ecosystem_auth)`), add the identical dependency to the PUT and DELETE routes here. Read the neighbouring `/ai-profile` PUT route and match it exactly.

- [ ] **Step 5: Run to verify it passes**

```bash
~/.local/share/ecosystem/venv/bin/python -m pytest tests/test_provider_key_endpoints.py -v
```
Expected: 6 passed

- [ ] **Step 6: Confirm no key can leak into logs**

```bash
grep -nE 'logger.*(api_key|body\.api_key)|print\(.*api_key' registry/app.py registry/credential_store.py
```
Expected: no output.

- [ ] **Step 7: Run the full registry suite**

```bash
~/.local/share/ecosystem/venv/bin/python -m pytest tests/ -q
```
Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git -C /Volumes/Locker2/GitHub/appEcosystem add registry/app.py tests/test_provider_key_endpoints.py
git -C /Volumes/Locker2/GitHub/appEcosystem commit -m "feat(registry): endpoints to set/list/delete provider API keys

GET returns only configured/last4; PUT and DELETE are loopback-gated and
404-cloaked, matching the ecosystem-secret endpoint precedent."
```

---

### Task 3: Resolve provider keys from the store in `ecosystem_ai`

`build_providers()` constructs cloud providers with "api_key resolved from env", so a key stored by Task 1 would be ignored. Add store-backed resolution while keeping env vars working.

**Files:**
- Modify: `appEcosystem/packages/ecosystem-ai/ecosystem_ai/factory.py` (`build_providers`, ~line 27-40)
- Create: `appEcosystem/packages/ecosystem-ai/tests/test_key_resolution.py`

**Interfaces:**
- Consumes: `ProviderCredentialStore` (Task 1) — imported defensively, since `ecosystem_ai` may be installed without the registry package.
- Produces: `resolve_provider_key(provider) -> str | None` in `factory.py`. Task 5 (harness) relies on `build_router()` picking keys up automatically.

- [ ] **Step 1: Write the failing test**

Create `appEcosystem/packages/ecosystem-ai/tests/test_key_resolution.py`:

```python
"""Cloud provider keys resolve from the credential store, then env."""
import pytest

from ecosystem_ai.factory import build_providers, resolve_provider_key
from ecosystem_ai.profile import AIProfile, CloudProvider


def test_store_key_is_used(monkeypatch, tmp_path):
    monkeypatch.setenv("ECOSYSTEM_PROVIDER_KEYS_FILE", str(tmp_path / "keys.json"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from registry.credential_store import ProviderCredentialStore

    ProviderCredentialStore(path=str(tmp_path / "keys.json")).set_key(
        "anthropic", "sk-test-000000001111"
    )
    assert resolve_provider_key("anthropic") == "sk-test-000000001111"


def test_env_var_is_the_fallback(monkeypatch, tmp_path):
    monkeypatch.setenv("ECOSYSTEM_PROVIDER_KEYS_FILE", str(tmp_path / "absent.json"))
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-000000002222")
    assert resolve_provider_key("openai") == "sk-test-000000002222"


def test_enabled_cloud_provider_receives_the_stored_key(monkeypatch, tmp_path):
    monkeypatch.setenv("ECOSYSTEM_PROVIDER_KEYS_FILE", str(tmp_path / "keys.json"))
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    from registry.credential_store import ProviderCredentialStore

    ProviderCredentialStore(path=str(tmp_path / "keys.json")).set_key(
        "openai", "sk-test-000000003333"
    )
    profile = AIProfile()
    profile.cloud["openai"] = CloudProvider(enabled=True, model="gpt-4o-mini")
    providers = build_providers(profile)
    assert providers["openai"].api_key == "sk-test-000000003333"


def test_no_key_anywhere_returns_none(monkeypatch, tmp_path):
    monkeypatch.setenv("ECOSYSTEM_PROVIDER_KEYS_FILE", str(tmp_path / "absent.json"))
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    assert resolve_provider_key("gemini") is None
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd /Volumes/Locker2/GitHub/appEcosystem
~/.local/share/ecosystem/venv/bin/python -m pytest packages/ecosystem-ai/tests/test_key_resolution.py -v
```
Expected: FAIL — `ImportError: cannot import name 'resolve_provider_key'`

- [ ] **Step 3: Implement resolution**

In `packages/ecosystem-ai/ecosystem_ai/factory.py`, add above `build_providers`:

```python
import os

# Env var each provider historically read, kept as the fallback so existing
# environment-based deployments keep working unchanged.
_ENV_VARS = {
    "anthropic": ("ANTHROPIC_API_KEY",),
    "openai": ("OPENAI_API_KEY",),
    "gemini": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
}


def resolve_provider_key(provider: str) -> Optional[str]:
    """Credential store first, then the provider's env var(s).

    The store is what the UI and `ecosystem provider` CLI write, so it takes
    precedence; env vars remain a valid way to configure a service.
    """
    try:
        from registry.credential_store import ProviderCredentialStore

        key = ProviderCredentialStore().get_key(provider)
        if key:
            return key
    except Exception:
        # ecosystem_ai can be installed without the registry package.
        pass
    for var in _ENV_VARS.get(provider, ()):
        val = os.environ.get(var)
        if val:
            return val
    return None
```

Then in `build_providers`, pass the resolved key:

```python
    for name, cls in _CLOUD_CLASSES.items():
        cfg = profile.cloud.get(name)
        if cfg and cfg.enabled:
            kwargs = {}
            if cfg.model:
                kwargs["default_model"] = cfg.model
            key = resolve_provider_key(name)
            if key:
                kwargs["api_key"] = key
            providers[name] = cls(**kwargs)
    return providers
```

- [ ] **Step 4: Run to verify it passes**

```bash
~/.local/share/ecosystem/venv/bin/python -m pytest packages/ecosystem-ai/tests/test_key_resolution.py -v
```
Expected: 4 passed

- [ ] **Step 5: Confirm local-first is untouched**

```bash
~/.local/share/ecosystem/venv/bin/python -c "
from ecosystem_ai.profile import AIProfile
from ecosystem_ai.factory import build_providers
p = AIProfile()
print('default_provider:', p.default_provider)
print('providers with no cloud enabled:', sorted(build_providers(p)))
"
```
Expected: `default_provider: ollama` and `['ollama']` — no cloud provider is constructed unless explicitly enabled.

- [ ] **Step 6: Commit**

```bash
git -C /Volumes/Locker2/GitHub/appEcosystem add packages/ecosystem-ai/ecosystem_ai/factory.py packages/ecosystem-ai/tests/test_key_resolution.py
git -C /Volumes/Locker2/GitHub/appEcosystem commit -m "feat(ai): resolve cloud provider keys from the credential store

build_providers() only read API keys from the environment, so keys entered by a
user were ignored. Resolution is now store-first with the env var as fallback.
Local-first is unchanged: no cloud provider is built unless explicitly enabled."
```

---

### Task 4: `ecosystem provider` CLI

**Files:**
- Modify: `appEcosystem/cli/commands.py` (add `cmd_provider`, beside the existing `cmd_secret` at ~line 442)
- Modify: `appEcosystem/cli/main.py` (register the subcommand, beside the existing entries at ~line 40 and ~line 71)
- Create: `appEcosystem/tests/test_provider_cli.py`

**Interfaces:**
- Consumes: `ProviderCredentialStore` (Task 1).
- Produces: `ecosystem provider list|set <name>|delete <name>`.

- [ ] **Step 1: Write the failing test**

Create `appEcosystem/tests/test_provider_cli.py`:

```python
"""`ecosystem provider` never echoes a key."""
import pytest

from cli.commands import cmd_provider
from registry.credential_store import ProviderCredentialStore


@pytest.fixture(autouse=True)
def _keys(tmp_path, monkeypatch):
    monkeypatch.setenv("ECOSYSTEM_PROVIDER_KEYS_FILE", str(tmp_path / "keys.json"))


def test_list_shows_masked_status(capsys):
    ProviderCredentialStore().set_key("anthropic", "sk-test-000000005555")
    assert cmd_provider("list") == 0
    out = capsys.readouterr().out
    assert "anthropic" in out and "5555" in out
    assert "sk-test-000000005555" not in out


def test_set_stores_without_echoing(capsys):
    assert cmd_provider("set", "openai", "sk-test-000000006666") == 0
    assert ProviderCredentialStore().get_key("openai") == "sk-test-000000006666"
    assert "sk-test-000000006666" not in capsys.readouterr().out


def test_delete_removes(capsys):
    ProviderCredentialStore().set_key("gemini", "sk-test-000000000000")
    assert cmd_provider("delete", "gemini") == 0
    assert ProviderCredentialStore().get_key("gemini") is None


def test_unknown_provider_is_an_error():
    assert cmd_provider("set", "hackerllm", "sk-test-000000000000") != 0
```

- [ ] **Step 2: Run to verify it fails**

```bash
~/.local/share/ecosystem/venv/bin/python -m pytest tests/test_provider_cli.py -v
```
Expected: FAIL — `ImportError: cannot import name 'cmd_provider'`

- [ ] **Step 3: Implement the command**

In `cli/commands.py`:

```python
def cmd_provider(action: str, name: str | None = None, value: str | None = None) -> int:
    """Manage cloud AI provider API keys (anthropic / openai / gemini)."""
    from registry.credential_store import SUPPORTED_PROVIDERS, ProviderCredentialStore

    store = ProviderCredentialStore()

    if action == "list":
        for prov, st in store.status().items():
            state = f"configured (…{st['last4']})" if st["configured"] else "not configured"
            print(f"  {prov:<10} {state}")
        return 0

    if not name:
        print(f"Usage: ecosystem provider {action} <{'|'.join(SUPPORTED_PROVIDERS)}>")
        return 2

    if action == "set":
        key = value
        if not key:
            # Prompt without echoing so the key never lands in shell history or the screen.
            import getpass

            key = getpass.getpass(f"Paste the {name} API key (input hidden): ")
        try:
            store.set_key(name, key)
        except ValueError as e:
            print(f"Error: {e}")
            return 1
        print(f"Stored {name} key (…{store.status()[name]['last4']}).")
        return 0

    if action == "delete":
        if name not in SUPPORTED_PROVIDERS:
            print(f"Error: unknown provider {name!r}")
            return 1
        print(f"Deleted {name} key." if store.delete_key(name) else f"No {name} key was stored.")
        return 0

    print(f"Unknown action {action!r}. Use: list | set | delete")
    return 2
```

In `cli/main.py`, add the import beside `cmd_uninstall`, register the parser beside the other subparsers:

```python
    p_provider = sub.add_parser("provider", help="Manage cloud AI provider API keys")
    p_provider.add_argument("action", choices=["list", "set", "delete"])
    p_provider.add_argument("name", nargs="?", help="anthropic | openai | gemini")
    p_provider.add_argument("value", nargs="?", help="key (omit to be prompted without echo)")
```

and add to the dispatch table:

```python
        "provider": lambda args: cmd_provider(args.action, args.name, args.value),
```

Match the surrounding dispatch style — if other entries are bare function references invoked with parsed args, follow that convention instead of a lambda.

- [ ] **Step 4: Run to verify it passes**

```bash
~/.local/share/ecosystem/venv/bin/python -m pytest tests/test_provider_cli.py -v
```
Expected: 4 passed

- [ ] **Step 5: Smoke-test the real CLI (fake key)**

```bash
~/.local/share/ecosystem/venv/bin/python -m cli.main provider set openai sk-test-000000009999
~/.local/share/ecosystem/venv/bin/python -m cli.main provider list
~/.local/share/ecosystem/venv/bin/python -m cli.main provider delete openai
```
Expected: stores, lists `openai configured (…9999)`, then deletes. No full key printed.

- [ ] **Step 6: Commit**

```bash
git -C /Volumes/Locker2/GitHub/appEcosystem add cli/commands.py cli/main.py tests/test_provider_cli.py
git -C /Volumes/Locker2/GitHub/appEcosystem commit -m "feat(cli): ecosystem provider list|set|delete

Terminal management of cloud AI keys. 'set' without a value prompts with
getpass so the key never reaches shell history or the screen."
```

---

### Task 5: Harness daemon uses the shared AI profile and provider router

`daemon/aegissiem_daemon.py`'s `post_analyze` builds a prompt then calls Ollama directly via `OLLAMA_HOST`. It must instead honour the ecosystem AI profile, so a user who enables Claude/Gemini/OpenAI gets that provider — and so it never diverges from local model selection.

**Files:**
- Create: `CybersecurityTeam/cyber-claude-agents/daemon/llm_backend.py`
- Modify: `CybersecurityTeam/cyber-claude-agents/daemon/aegissiem_daemon.py` (`post_analyze`, ~line 216-255)
- Create: `CybersecurityTeam/cyber-claude-agents/tests/test_llm_backend.py`

**Interfaces:**
- Consumes: `ecosystem_ai.build_router`, `ecosystem_ai.AIProfileClient`, and `resolve_provider_key` (Task 3).
- Produces: `async analyze(prompt: str) -> str` and `describe_backend() -> dict` in `daemon/llm_backend.py`.

- [ ] **Step 1: Write the failing test**

Create `CybersecurityTeam/cyber-claude-agents/tests/test_llm_backend.py`:

```python
"""The daemon's LLM backend follows the ecosystem AI profile."""
import pytest

from daemon import llm_backend


class _FakeRouter:
    def __init__(self, reply="analysis-result"):
        self.reply = reply
        self.calls = []

    async def complete(self, prompt, **kw):
        self.calls.append(prompt)
        return self.reply


@pytest.mark.asyncio
async def test_analyze_uses_the_router(monkeypatch):
    fake = _FakeRouter()
    monkeypatch.setattr(llm_backend, "_build_router", lambda: fake)
    out = await llm_backend.analyze("threat prompt")
    assert out == "analysis-result"
    assert fake.calls == ["threat prompt"]


def test_describe_backend_reports_provider_without_keys(monkeypatch):
    monkeypatch.setattr(llm_backend, "_load_profile", lambda: {"default_provider": "ollama"})
    desc = llm_backend.describe_backend()
    assert desc["provider"] == "ollama"
    assert "api_key" not in desc and "key" not in desc


@pytest.mark.asyncio
async def test_router_failure_surfaces_a_clean_error(monkeypatch):
    class _Broken:
        async def complete(self, prompt, **kw):
            raise RuntimeError("provider exploded")

    monkeypatch.setattr(llm_backend, "_build_router", lambda: _Broken())
    with pytest.raises(llm_backend.AnalysisUnavailable):
        await llm_backend.analyze("x")
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd /Volumes/Locker2/GitHub/CybersecurityTeam/cyber-claude-agents
~/.local/share/cyber-harness/venv/bin/python -m pytest tests/test_llm_backend.py -v
```
Expected: FAIL — `ModuleNotFoundError: No module named 'daemon.llm_backend'`
(If the harness venv does not exist yet, Task 6 creates it — run Task 6 first and return here, or use any venv with `ecosystem_ai` installed.)

- [ ] **Step 3: Implement the backend**

Create `daemon/llm_backend.py`:

```python
"""LLM access for the harness daemon, driven by the ecosystem AI profile.

The daemon previously called Ollama directly. It now goes through
ecosystem_ai's ProviderRouter, so whichever provider the user selected —
local Ollama or an enabled cloud provider — is honoured. This module is a
pure CONSUMER of the profile: it never writes it, so it cannot disturb the
local model selection that AI-for-Survival manages.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Optional

logger = logging.getLogger(__name__)

REGISTRY_URL = os.environ.get("ECOSYSTEM_REGISTRY_URL", "http://localhost:8500")


class AnalysisUnavailable(RuntimeError):
    """Raised when no configured provider could answer."""


def _load_profile() -> dict[str, Any]:
    """Fetch the ecosystem AI profile, falling back to local defaults."""
    try:
        import httpx

        r = httpx.get(f"{REGISTRY_URL}/ai-profile", timeout=4)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        logger.debug("Could not fetch ai-profile from registry: %s", e)
    try:
        from ecosystem_ai.profile import default_profile

        prof = default_profile()
        return prof.__dict__ if hasattr(prof, "__dict__") else dict(prof)
    except Exception:
        return {"default_provider": "ollama"}


def _build_router():
    from ecosystem_ai.factory import build_router
    from ecosystem_ai.profile import AIProfile

    data = _load_profile()
    profile = AIProfile(**{k: v for k, v in data.items() if k in AIProfile.__dataclass_fields__})
    return build_router(profile)


def describe_backend() -> dict[str, Any]:
    """Non-secret description of the active backend, safe to log and expose."""
    prof = _load_profile()
    return {
        "provider": prof.get("default_provider", "ollama"),
        "model": prof.get("selected_model", "auto"),
        "allow_cloud_fallback": prof.get("allow_cloud_fallback", False),
    }


async def analyze(prompt: str, context: Optional[str] = None) -> str:
    """Run a security-analysis completion through the selected provider."""
    if context:
        prompt = f"{prompt}\n\nAdditional context:\n{context}"
    try:
        router = _build_router()
        return await router.complete(prompt)
    except Exception as e:
        # Never include provider credentials or raw response bodies here.
        logger.warning("LLM analysis failed: %s", e.__class__.__name__)
        raise AnalysisUnavailable("No configured AI provider could complete the request") from e
```

If `ProviderRouter` exposes a differently named completion method, read `packages/ecosystem-ai/ecosystem_ai/router.py` and call the real one — keep `analyze()`'s own signature as specified.

- [ ] **Step 4: Replace the hardcoded Ollama call**

In `daemon/aegissiem_daemon.py`'s `post_analyze`, keep the existing prompt-building (including the recent-threats block) and replace the direct Ollama call with:

```python
        from .llm_backend import AnalysisUnavailable, analyze

        try:
            answer = await analyze(prompt, context=body.get("context") or None)
        except AnalysisUnavailable as e:
            return web.json_response({"error": str(e)}, status=503)
        return web.json_response({"analysis": answer, "backend": describe_backend()})
```

Add `describe_backend` to the same import. Remove the now-dead `ollama_url = os.environ.get("OLLAMA_HOST", ...)` line and the HTTP call that followed it.

- [ ] **Step 5: Run to verify it passes**

```bash
~/.local/share/cyber-harness/venv/bin/python -m pytest tests/test_llm_backend.py -v
```
Expected: 3 passed

- [ ] **Step 6: Confirm the daemon never writes the profile**

```bash
grep -rnE 'PUT.*ai-profile|put\(.*ai-profile|update_ai_profile' daemon/
```
Expected: no output — the daemon only reads the profile.

- [ ] **Step 7: Commit**

```bash
cd /Volumes/Locker2/GitHub/CybersecurityTeam/cyber-claude-agents
git add daemon/llm_backend.py daemon/aegissiem_daemon.py tests/test_llm_backend.py
git commit -m "feat(daemon): route analysis through the ecosystem provider router

post_analyze called Ollama directly, ignoring the user's provider choice. It now
uses ecosystem_ai's router, so Claude/Gemini/OpenAI work when enabled. The daemon
only reads the AI profile, so it cannot disturb local model selection."
```

---

### Task 6: Harness install/uninstall with single-owner enforcement

**Files:**
- Create: `CybersecurityTeam/cyber-claude-agents/scripts/install-local.sh`
- Create: `CybersecurityTeam/cyber-claude-agents/scripts/uninstall.sh`
- Create: `CybersecurityTeam/cyber-claude-agents/scripts/uninstall-keep-data.sh`
- Modify: `CybersecurityTeam/cyber-claude-agents/daemon/aegissiem_daemon.py` (startup guard)
- Modify: `appEcosystem/ecosystem.yaml` (`aegissiem_daemon.start_command`, ~line 138)

**Interfaces:**
- Produces: launchd label `com.smartindustries.cyber-harness`, runtime `~/.local/share/cyber-harness/venv`, state `~/.cyber-harness`, service on 8088.

- [ ] **Step 1: Write the failing assertion**

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8088/api/status
```
Expected now: `000` (nothing listening).

- [ ] **Step 2: Add the single-instance guard to the daemon**

In `daemon/aegissiem_daemon.py`, before the web app starts listening, add:

```python
def _abort_if_already_serving(port: int) -> None:
    """Exactly one harness daemon per machine.

    launchd is the sole owner. `ecosystem start-all` and a manual run are both
    possible second start vectors, and two daemons on one SQLite state dir would
    double-count threats and double-fire auto-block actions.
    """
    import httpx

    try:
        r = httpx.get(f"http://127.0.0.1:{port}/api/status", timeout=2)
        if r.status_code == 200:
            logger.error(
                "A harness daemon is already serving on port %s — exiting. "
                "launchd owns this service (com.smartindustries.cyber-harness).",
                port,
            )
            raise SystemExit(0)
    except SystemExit:
        raise
    except Exception:
        pass  # Nothing healthy there: we are the owner.
```

Call it with the configured port immediately before binding.

- [ ] **Step 3: Remove the second start vector**

In `appEcosystem/ecosystem.yaml`, under `aegissiem_daemon`, replace the `start_command` line with:

```yaml
    # No start_command: launchd (com.smartindustries.cyber-harness) is the sole
    # owner of this daemon. Two instances would share one SQLite state dir and
    # double-fire auto-block actions. Install/enable it with:
    #   CybersecurityTeam/cyber-claude-agents/scripts/install-local.sh --plist
    start_command: ""
```

Confirm `cmd_start_all` skips services with an empty `start_command`; if it does not, add that guard in `cli/commands.py` and note it in the commit.

- [ ] **Step 4: Create the installer**

Create `scripts/install-local.sh` — same structure as `LogAnalysis/scripts/install-local.sh`:

```bash
#!/usr/bin/env bash
# Install the Cyber Claude harness daemon (aegissiem_daemon, port 8088).
#
# Bundled but OPT-IN: this sets the runtime up; the daemon only runs when you
# install the LaunchAgent with --plist. Runtime lives on the INTERNAL disk (the
# repo may sit on an external volume, where a force-unmount SIGBUSes mmap'd
# C-extensions).
#
#   ./scripts/install-local.sh            # venv + deps only (no service)
#   ./scripts/install-local.sh --plist    # also install + load the LaunchAgent
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${CYBER_HARNESS_PREFIX:-$HOME/.local/share/cyber-harness}"
VENV="$PREFIX/venv"
PY="${PYTHON_BIN:-python3.12}"
PORT="${CYBER_HARNESS_PORT:-8088}"
LABEL="com.smartindustries.cyber-harness"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
WRITE_PLIST=false
for a in "$@"; do case "$a" in --plist) WRITE_PLIST=true ;; esac; done

echo "==> Installing cyber-harness runtime to $PREFIX"
mkdir -p "$PREFIX" "$HOME/.cyber-harness"
[ -d "$VENV" ] || "$PY" -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip wheel >/dev/null
[ -f "$REPO/daemon/requirements.txt" ] && "$VENV/bin/pip" install -r "$REPO/daemon/requirements.txt"
"$VENV/bin/pip" install "$REPO"

ECO_ROOT="${ECOSYSTEM_BASE_PATH:-$REPO/../..}/appEcosystem"
if [ -d "$ECO_ROOT" ]; then
    echo "==> Installing shared ecosystem packages from $ECO_ROOT"
    "$VENV/bin/pip" install "$ECO_ROOT/auth/python" "$ECO_ROOT/packages/ecosystem-client" \
                            "$ECO_ROOT/packages/ecosystem-ai"
else
    echo "!!  appEcosystem not found at $ECO_ROOT — provider routing unavailable" >&2
fi

if $WRITE_PLIST; then
    LOGDIR="$HOME/Library/Logs/CyberHarness"
    mkdir -p "$LOGDIR" "$HOME/Library/LaunchAgents"
    cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array>
    <string>$VENV/bin/python</string>
    <string>-m</string><string>daemon.aegissiem_daemon</string>
  </array>
  <key>WorkingDirectory</key><string>$REPO</string>
  <key>EnvironmentVariables</key><dict>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
    <key>HOME</key><string>$HOME</string>
    <key>CYBER_HARNESS_PORT</key><string>$PORT</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$LOGDIR/stdout.log</string>
  <key>StandardErrorPath</key><string>$LOGDIR/stderr.log</string>
</dict></plist>
PLIST_EOF
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
    launchctl bootstrap "gui/$(id -u)" "$PLIST"
    echo "==> LaunchAgent loaded ($LABEL, port $PORT)"
else
    echo "==> Runtime ready (opt-in). Enable the service with: $0 --plist"
fi
```

- [ ] **Step 5: Create both uninstallers**

Create `scripts/uninstall.sh` following the exact structure of `LogAnalysis/scripts/uninstall.sh` (full removal by default; `--keep-data`, `-y/--yes`, `--dry-run`, `-h`; confirm-gated). It removes: the LaunchAgent `$PLIST`, any stray `daemon.aegissiem_daemon` process, `$PREFIX`, `~/Library/Logs/CyberHarness`, and — unless `--keep-data` — `~/.cyber-harness`. It must touch no other project's directory.

Create `scripts/uninstall-keep-data.sh`:

```bash
#!/usr/bin/env bash
# Uninstall the cyber-harness daemon but KEEP local state (~/.cyber-harness:
# detection history, honeypot events, SQLite DBs).
#
# For a complete wipe use ./scripts/uninstall.sh
set -euo pipefail
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/uninstall.sh" --keep-data "$@"
```

- [ ] **Step 6: Syntax-check, install, and verify**

```bash
cd /Volumes/Locker2/GitHub/CybersecurityTeam/cyber-claude-agents
chmod +x scripts/*.sh
for s in scripts/install-local.sh scripts/uninstall.sh scripts/uninstall-keep-data.sh; do bash -n "$s" && echo "OK $s"; done
bash scripts/uninstall.sh --dry-run --yes
ECOSYSTEM_BASE_PATH=/Volumes/Locker2/GitHub bash scripts/install-local.sh --plist
sleep 20
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8088/api/status
```
Expected: three `OK`s; a dry-run touching only harness-owned paths; then `200`.

- [ ] **Step 7: Prove the dedup guard works**

```bash
cd /Volumes/Locker2/GitHub/CybersecurityTeam/cyber-claude-agents
~/.local/share/cyber-harness/venv/bin/python -m daemon.aegissiem_daemon; echo "exit=$?"
```
Expected: logs "already serving on port 8088 — exiting" and `exit=0`. Then confirm the launchd instance is still the only one:
```bash
pgrep -fc 'daemon.aegissiem_daemon'
```
Expected: `1`

- [ ] **Step 8: Commit both repos**

```bash
cd /Volumes/Locker2/GitHub/CybersecurityTeam/cyber-claude-agents
git add scripts/ daemon/aegissiem_daemon.py
git commit -m "feat(install): opt-in installer, uninstallers, and single-instance guard

Adds an internal-disk installer (service only with --plist), the standard
full-purge and keep-data uninstallers, and a startup guard so a second daemon
exits instead of sharing the SQLite state dir and double-firing auto-blocks."

git -C /Volumes/Locker2/GitHub/appEcosystem add ecosystem.yaml
git -C /Volumes/Locker2/GitHub/appEcosystem commit -m "fix(config): launchd is the sole owner of the harness daemon

Clears aegissiem_daemon's start_command so 'ecosystem start-all' cannot become a
second start vector for a service launchd already supervises."
```

---

### Task 7: Bundle harness availability into the AegisSIEM and appEcosystem installers

"Available when needed" — the harness should be set up by the installers of the two projects that depend on it, without being started.

**Files:**
- Modify: `LogAnalysis/scripts/install-local.sh` (after the shared-package block, ~line 55-60)
- Modify: `appEcosystem/scripts/install-local.sh` (after the shared-secret block, ~line 44-47)
- Modify: `LogAnalysis/scripts/uninstall.sh` (must NOT remove the harness — verify only)

**Interfaces:**
- Consumes: `scripts/install-local.sh` from Task 6.

- [ ] **Step 1: Add opt-in harness setup to the AegisSIEM installer**

In `LogAnalysis/scripts/install-local.sh`, after the shared ecosystem packages block:

```bash
# The cyber-harness daemon (port 8088) is AegisSIEM's preferred analysis backend.
# Set its runtime up so it is available when needed; do NOT start it (opt-in) and
# do NOT fail this install if it is absent.
HARNESS="${CYBER_HARNESS_PATH:-${ECOSYSTEM_BASE_PATH:-$REPO/..}/CybersecurityTeam/cyber-claude-agents}"
if [ -x "$HARNESS/scripts/install-local.sh" ]; then
    if [ -n "${AEGIS_SKIP_HARNESS:-}" ]; then
        echo "==> AEGIS_SKIP_HARNESS=1 — skipping cyber-harness setup."
    else
        echo "==> Preparing cyber-harness runtime (opt-in; enable with --plist)"
        ECOSYSTEM_BASE_PATH="${ECOSYSTEM_BASE_PATH:-$REPO/..}" \
            "$HARNESS/scripts/install-local.sh" || echo "!!  cyber-harness setup skipped (non-fatal)"
    fi
else
    echo "==> cyber-harness not present at $HARNESS — skipping (optional component)."
fi
```

- [ ] **Step 2: Mirror it in the appEcosystem installer**

Add the same block to `appEcosystem/scripts/install-local.sh` after the shared-secret provisioning, using `$REPO/..` as the search root and `ECOSYSTEM_SKIP_HARNESS` as the opt-out.

- [ ] **Step 3: Verify AegisSIEM's uninstaller does not remove the harness**

```bash
bash /Volumes/Locker2/GitHub/LogAnalysis/scripts/uninstall.sh --dry-run --yes | grep -E 'cyber-harness|cyber-claude' && echo "LEAK — fix it" || echo "OK: AegisSIEM uninstall leaves the harness alone"
```
Expected: `OK: ...`. If it leaks, remove the offending line — each uninstaller owns only its own paths.

- [ ] **Step 4: Verify a bundled install prepares but does not start**

```bash
bash /Volumes/Locker2/GitHub/CybersecurityTeam/cyber-claude-agents/scripts/uninstall.sh --yes
cd /Volumes/Locker2/GitHub/LogAnalysis
ECOSYSTEM_BASE_PATH=/Volumes/Locker2/GitHub bash scripts/install-local.sh
test -d ~/.local/share/cyber-harness/venv && echo "OK: runtime prepared"
test -f ~/Library/LaunchAgents/com.smartindustries.cyber-harness.plist \
  && echo "FAIL: started without opt-in" || echo "OK: not started (opt-in respected)"
```
Expected: `OK: runtime prepared` and `OK: not started (opt-in respected)`.

- [ ] **Step 5: Commit both repos**

```bash
git -C /Volumes/Locker2/GitHub/LogAnalysis add scripts/install-local.sh
git -C /Volumes/Locker2/GitHub/LogAnalysis commit -m "feat(install): prepare the cyber-harness runtime (opt-in, non-fatal)"
git -C /Volumes/Locker2/GitHub/appEcosystem add scripts/install-local.sh
git -C /Volumes/Locker2/GitHub/appEcosystem commit -m "feat(install): prepare the cyber-harness runtime (opt-in, non-fatal)"
```

---

### Task 8: Provider & key management UI — AI-for-Survival

AFS is the ecosystem's AI hub and already has a system-settings surface with model management, so this is the primary UI.

**Files:**
- Create: `AI-for-Survival/backend/src/api/v1/providers.py`
- Modify: `AI-for-Survival/backend/src/api/main.py` (register the router beside the other v1 routers)
- Create: `AI-for-Survival/frontend/src/components/Settings/ProviderKeys.tsx`
- Modify: the AFS system-settings page to render `<ProviderKeys />`
- Create: `AI-for-Survival/backend/tests/test_providers_api.py`

**Interfaces:**
- Consumes: registry endpoints from Task 2 (`GET /ai/providers`, `PUT|DELETE /ai/providers/{provider}/key`).
- Produces: AFS-proxied `GET /api/v1/providers`, `PUT /api/v1/providers/{provider}/key`, `DELETE /api/v1/providers/{provider}/key` — admin-only.

- [ ] **Step 1: Write the failing backend test**

Create `AI-for-Survival/backend/tests/test_providers_api.py`:

```python
"""AFS provider-key proxy: admin-gated, never returns a key."""
import pytest


def test_list_requires_admin(client):
    r = client.get("/api/v1/providers")
    assert r.status_code in (401, 403)


def test_admin_sees_masked_status(admin_client, monkeypatch):
    from src.api.v1 import providers

    monkeypatch.setattr(
        providers, "_registry_get",
        lambda path: {"providers": {"anthropic": {"configured": True, "last4": "9999", "updated_at": ""}}},
    )
    r = admin_client.get("/api/v1/providers")
    assert r.status_code == 200
    assert r.json()["providers"]["anthropic"]["last4"] == "9999"


def test_set_key_is_not_echoed(admin_client, monkeypatch):
    from src.api.v1 import providers

    seen = {}

    def _put(path, json=None):
        seen["body"] = json
        return {"status": "stored", "provider": "openai", "last4": "4321"}

    monkeypatch.setattr(providers, "_registry_put", _put)
    r = admin_client.put("/api/v1/providers/openai/key", json={"api_key": "sk-test-000000004321"})
    assert r.status_code == 200
    assert "sk-test-000000004321" not in r.text
    assert seen["body"]["api_key"] == "sk-test-000000004321"
```

Use whatever `client` / `admin_client` fixtures the AFS suite already provides — read `backend/tests/conftest.py` and match them. If no admin fixture exists, create one following the existing auth-test patterns.

- [ ] **Step 2: Run to verify it fails**

```bash
cd /Volumes/Locker2/GitHub/AI-for-Survival
~/.local/share/ai-survival/venv/bin/python -m pytest backend/tests/test_providers_api.py -v
```
Expected: FAIL (router does not exist).

- [ ] **Step 3: Implement the proxy router**

Create `backend/src/api/v1/providers.py` with `_registry_get`, `_registry_put`, `_registry_delete` helpers that call the registry over loopback using `ecosystem_auth.sign_request` (match how other AFS code reaches the registry), and three routes gated on the existing `get_current_admin_user` dependency. The proxy must:
- return the registry's masked status verbatim for GET,
- forward `api_key` for PUT and return only `{status, provider, last4}`,
- never log the request body.

- [ ] **Step 4: Build the UI component**

Create `frontend/src/components/Settings/ProviderKeys.tsx` rendering one row per provider (`anthropic`, `openai`, `gemini`) with:
- the masked state — "Not configured" or "Configured ••••1234 · updated <date>",
- a password-type input plus **Save** (calls PUT, then re-fetches status and clears the input),
- a **Delete** button (confirm first, then DELETE + re-fetch),
- an explanatory line: keys are stored on this machine at `~/.config/ecosystem/provider_keys.json` (mode 600) and are never displayed again after saving.

The input MUST be `type="password"` with `autoComplete="off"`, and the component must never place a key in component state that is persisted or logged.

- [ ] **Step 5: Render it in system settings**

Add `<ProviderKeys />` to the AFS system-settings page, below the existing model-management section. Local model selection stays the primary control; this section is titled "Cloud AI providers (optional)".

- [ ] **Step 6: Verify**

```bash
~/.local/share/ai-survival/venv/bin/python -m pytest backend/tests/test_providers_api.py -v
cd frontend && npx tsc --noEmit && npm run build
```
Expected: tests pass, `tsc` clean, build succeeds.

- [ ] **Step 7: Commit**

```bash
git -C /Volumes/Locker2/GitHub/AI-for-Survival add backend/src/api/v1/providers.py backend/src/api/main.py \
  backend/tests/test_providers_api.py frontend/src/components/Settings/ProviderKeys.tsx
git -C /Volumes/Locker2/GitHub/AI-for-Survival commit -m "feat(settings): manage cloud AI provider keys from the UI

Admin-only proxy to the registry's provider-key endpoints plus a settings panel
to add, replace, and delete Claude/Gemini/OpenAI keys. Keys are write-only from
the UI's perspective — status shows only the last four characters."
```

---

### Task 9: Provider & key management UI — OpenEye

OpenEye has `backend/core/ecosystem_ai_bridge.py` and a settings surface, so it is a relevant project.

**Files:**
- Create: `OpenEye-OpenCV_Home_Security/opencv_surveillance/backend/api/routes/ai_providers.py`
- Modify: `opencv_surveillance/backend/main.py` (include the router beside the other route includes)
- Create: `opencv_surveillance/frontend/src/pages/AIProviderSettingsPage.jsx`
- Modify: the OpenEye settings navigation to expose the page
- Create: `opencv_surveillance/tests/test_ai_providers_route.py`

**Interfaces:**
- Consumes: registry endpoints from Task 2. Same masked contract as Task 8.

- [ ] **Step 1: Write the failing test**

Create `opencv_surveillance/tests/test_ai_providers_route.py` asserting: the list route requires an authenticated admin; the response contains `configured`/`last4` and never a full key; and setting a key forwards it to the registry without echoing it. Match the fixtures used by OpenEye's existing route tests.

- [ ] **Step 2: Run to verify it fails**

```bash
cd /Volumes/Locker2/GitHub/OpenEye-OpenCV_Home_Security/opencv_surveillance
~/.local/share/openeye/venv/bin/python -m pytest tests/test_ai_providers_route.py -v
```
Expected: FAIL.

- [ ] **Step 3: Implement the route**

Create `backend/api/routes/ai_providers.py` mirroring Task 8's proxy: GET/PUT/DELETE against the registry over loopback with signed requests, gated on OpenEye's existing admin dependency, never logging the body. Register it in `backend/main.py`.

- [ ] **Step 4: Build the page**

Create `frontend/src/pages/AIProviderSettingsPage.jsx` with the same three-provider layout as Task 8 (masked status, password input + Save, Delete with confirm, explanatory line). Follow OpenEye's existing page conventions — look at `AlertSettingsPage.jsx` for structure and styling, and add a matching `.css` file if that page has one.

- [ ] **Step 5: Verify**

```bash
~/.local/share/openeye/venv/bin/python -m pytest tests/test_ai_providers_route.py -v
cd frontend && npm run build
```
Expected: tests pass, build succeeds.

- [ ] **Step 6: Commit**

```bash
git -C /Volumes/Locker2/GitHub/OpenEye-OpenCV_Home_Security add \
  opencv_surveillance/backend/api/routes/ai_providers.py opencv_surveillance/backend/main.py \
  opencv_surveillance/frontend/src/pages/AIProviderSettingsPage.jsx opencv_surveillance/tests/test_ai_providers_route.py
git -C /Volumes/Locker2/GitHub/OpenEye-OpenCV_Home_Security commit -m "feat(settings): cloud AI provider key management page"
```

---

### Task 10: Provider & key management UI — AegisSIEM dashboard

AegisSIEM consumes LLM analysis through the harness, so it needs the same control. Its dashboard is Flask + Jinja, not React.

**Files:**
- Modify: `LogAnalysis/src/aegissiem/dashboard/app.py` (add routes)
- Create: `LogAnalysis/src/aegissiem/dashboard/templates/ai_providers.html`
- Modify: `LogAnalysis/src/aegissiem/dashboard/templates/base.html` (nav entry)
- Create: `LogAnalysis/tests/test_dashboard_ai_providers.py`

**Interfaces:**
- Consumes: registry endpoints from Task 2. Same masked contract.

- [ ] **Step 1: Write the failing test**

Create `LogAnalysis/tests/test_dashboard_ai_providers.py` asserting: `GET /ai-providers` requires login and renders each provider's masked state; `POST /ai-providers/<provider>` forwards the key and redirects; the rendered HTML never contains a full key. Match the fixtures in AegisSIEM's existing dashboard tests.

- [ ] **Step 2: Run to verify it fails**

```bash
cd /Volumes/Locker2/GitHub/LogAnalysis
~/.local/share/aegissiem/venv/bin/python -m pytest tests/test_dashboard_ai_providers.py -v
```
Expected: FAIL.

- [ ] **Step 3: Add the routes**

In `dashboard/app.py`, add login-gated `GET /ai-providers`, `POST /ai-providers/<provider>` (set), and `POST /ai-providers/<provider>/delete`, each proxying to the registry over loopback. Follow the login-protection decorator the other dashboard routes use. Never log `request.form`.

- [ ] **Step 4: Create the template**

Create `templates/ai_providers.html` extending `base.html`, with a table of the three providers showing masked status, a `type="password"` input with a Save button per row, and a Delete button. Include the note that keys are stored locally at `~/.config/ecosystem/provider_keys.json` (mode 600) and never shown again. Add a nav link in `base.html` matching the existing nav style.

- [ ] **Step 5: Verify**

```bash
~/.local/share/aegissiem/venv/bin/python -m pytest tests/test_dashboard_ai_providers.py -v
```
Expected: pass. Then restart and eyeball the page:
```bash
launchctl kickstart -k gui/$(id -u)/com.mikelsmart.aegissiem
sleep 10
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8089/ai-providers
```
Expected: `200` or a redirect to login (`302`).

- [ ] **Step 6: Commit**

```bash
git -C /Volumes/Locker2/GitHub/LogAnalysis add src/aegissiem/dashboard/app.py \
  src/aegissiem/dashboard/templates/ai_providers.html src/aegissiem/dashboard/templates/base.html \
  tests/test_dashboard_ai_providers.py
git -C /Volumes/Locker2/GitHub/LogAnalysis commit -m "feat(dashboard): cloud AI provider key management page"
```

---

## Final Verification

- [ ] **No secret ever crosses a read path**

```bash
cd /Volumes/Locker2/GitHub/appEcosystem
~/.local/share/ecosystem/venv/bin/python -m cli.main provider set anthropic sk-test-999888777666
~/.local/share/ecosystem/venv/bin/python -c "
import httpx
r = httpx.get('http://127.0.0.1:8500/ai/providers', timeout=5)
assert 'sk-test-999888777666' not in r.text, 'KEY LEAKED'
print('masked status:', r.json()['providers']['anthropic'])
"
~/.local/share/ecosystem/venv/bin/python -m cli.main provider delete anthropic
```
Expected: `{'configured': True, 'last4': '7666', ...}` and no leak.

- [ ] **Key file permissions**

```bash
stat -f '%Sp %N' ~/.config/ecosystem/provider_keys.json 2>/dev/null || echo "(no key file — nothing configured)"
```
Expected: `-rw-------` when present.

- [ ] **Local-first is preserved**

```bash
~/.local/share/ecosystem/venv/bin/python -c "
import httpx
p = httpx.get('http://127.0.0.1:8500/ai-profile', timeout=5).json()
print('default_provider:', p.get('default_provider'))
print('selected_model:', p.get('selected_model'))
"
```
Expected: `ollama` and the user's existing model — unchanged by any of this work.

- [ ] **Exactly one harness daemon**

```bash
pgrep -fc 'daemon.aegissiem_daemon'
```
Expected: `1` (or `0` when the service is intentionally not enabled).

- [ ] **Registry does not advertise a dead 8088**

```bash
~/.local/share/ecosystem/venv/bin/python -c "
import httpx
d = httpx.get('http://127.0.0.1:8500/services', timeout=5).json()
svcs = d if isinstance(d, list) else d.get('services', [])
for s in svcs:
    if 'daemon' in (s.get('name') or ''):
        print(s.get('name'), s.get('base_url'), 'healthy=', s.get('healthy'))
"
```
Expected: `healthy=True` when enabled; when not enabled it must not be presented as an available backend.

- [ ] **No key appears in any log**

```bash
grep -rlE 'sk-(test|ant|proj)-[A-Za-z0-9_-]{8,}' ~/Library/Logs/*/ 2>/dev/null && echo "LEAK IN LOGS" || echo "OK: no keys in logs"
```
Expected: `OK: no keys in logs`
