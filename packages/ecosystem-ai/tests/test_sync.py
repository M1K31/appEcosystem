"""Tests for the client-side AI profile sync (B3 core)."""

import asyncio

from ecosystem_ai import AIProfileClient, default_profile


class _Resp:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeHTTP:
    def __init__(self, profile=None, fail=False):
        self._profile = profile or default_profile().to_dict()
        self.fail = fail
        self.calls = []

    async def get(self, url, headers=None, **kw):
        self.calls.append(("GET", url, headers))
        if self.fail:
            raise RuntimeError("unreachable")
        return _Resp(200, self._profile)

    async def put(self, url, json=None, headers=None, **kw):
        self.calls.append(("PUT", url, headers, json))
        if self.fail:
            raise RuntimeError("unreachable")
        prof = dict(self._profile)
        prof.update(json or {})
        prof["version"] = prof.get("version", 1) + 1
        self._profile = prof
        return _Resp(200, prof)


def test_fetch_returns_shared_profile():
    http = _FakeHTTP()
    c = AIProfileClient("http://reg:8500", client=http)
    prof = asyncio.run(c.fetch())
    assert prof.default_provider == "ollama"
    assert http.calls[0][0] == "GET"


def test_fetch_falls_back_to_local_when_unreachable():
    local = default_profile()
    local.selected_model = "local-only-model"
    http = _FakeHTTP(fail=True)
    c = AIProfileClient("http://reg:8500", client=http, local_profile=local)
    prof = asyncio.run(c.fetch())
    assert prof.selected_model == "local-only-model"


def test_update_propagates_and_returns_new_version():
    http = _FakeHTTP()
    c = AIProfileClient("http://reg:8500", service_name="afs", client=http)
    before = asyncio.run(c.fetch()).version
    prof = asyncio.run(c.update({"selected_model": "llama3.1:8b"}))
    assert prof.selected_model == "llama3.1:8b"
    assert prof.version == before + 1


def test_update_applies_locally_when_unreachable():
    http = _FakeHTTP(fail=True)
    c = AIProfileClient("http://reg:8500", service_name="afs", client=http)
    prof = asyncio.run(c.update({"selected_model": "mistral:7b"}))
    assert prof.selected_model == "mistral:7b"
    assert prof.updated_by == "afs"


def test_signer_is_used():
    recorded = {}

    def signer(method, url, body):
        recorded["sig"] = (method, url, body is not None)
        return {"X-Ecosystem-Signature": "sig"}

    http = _FakeHTTP()
    c = AIProfileClient("http://reg:8500", signer=signer, client=http)
    asyncio.run(c.update({"prefer": "cloud"}))
    assert recorded["sig"][0] == "PUT"
    # PUT headers carried the signature
    put_call = [x for x in http.calls if x[0] == "PUT"][0]
    assert put_call[2]["X-Ecosystem-Signature"] == "sig"


def test_on_profile_changed_updates_local_view():
    c = AIProfileClient("http://reg:8500")
    new = default_profile()
    new.selected_model = "from-event"
    updated = c.on_profile_changed({"profile": new.to_dict()})
    assert updated.selected_model == "from-event"
    assert c.local_profile.selected_model == "from-event"
