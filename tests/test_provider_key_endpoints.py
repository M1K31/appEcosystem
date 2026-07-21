"""Provider-key endpoints: masking, authz, loopback gating."""
import pytest
from fastapi.testclient import TestClient

from registry.app import app
from registry.credential_store import ProviderCredentialStore
from ecosystem_auth.tokens import sign_request

TEST_SECRET = "provider-key-test-secret"


@pytest.fixture(autouse=True)
def _store(tmp_path, monkeypatch):
    monkeypatch.setenv("ECOSYSTEM_PROVIDER_KEYS_FILE", str(tmp_path / "keys.json"))
    monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", TEST_SECRET)
    # Reset the process-wide nonce store so signed requests in this test
    # module don't collide with nonces left over from other test modules.
    from auth.python.ecosystem_auth import middleware
    middleware._nonce_store._seen.clear()
    store = ProviderCredentialStore(path=str(tmp_path / "keys.json"))
    app.state.provider_credential_store = store
    return store


@pytest.fixture
def client():
    # A genuine loopback host, not Starlette's "testclient" sentinel - the
    # production loopback allowlist no longer trusts that sentinel.
    return TestClient(app, client=("127.0.0.1", 50000))


def _auth_headers(method: str, path: str, body=None):
    url = f"http://testserver{path}"
    return sign_request(method, url, TEST_SECRET, body)


def test_get_lists_providers_without_keys(client, _store):
    _store.set_key("anthropic", "sk-test-000000009999")
    r = client.get("/ai/providers")
    assert r.status_code == 200
    body = r.json()["providers"]
    assert body["anthropic"]["configured"] is True
    assert body["anthropic"]["last4"] == "9999"
    assert "sk-test-000000009999" not in r.text


def test_put_stores_a_key(client, _store):
    body = {"api_key": "sk-test-000000004321"}
    headers = _auth_headers("PUT", "/ai/providers/openai/key", body)
    r = client.put("/ai/providers/openai/key", json=body, headers=headers)
    assert r.status_code == 200
    assert r.json()["last4"] == "4321"
    assert _store.get_key("openai") == "sk-test-000000004321"
    assert "sk-test-000000004321" not in r.text


def test_put_rejects_unknown_provider(client):
    body = {"api_key": "sk-test-000000000000"}
    headers = _auth_headers("PUT", "/ai/providers/hackerllm/key", body)
    r = client.put("/ai/providers/hackerllm/key", json=body, headers=headers)
    assert r.status_code == 400


def test_put_rejects_empty_key(client):
    body = {"api_key": "  "}
    headers = _auth_headers("PUT", "/ai/providers/openai/key", body)
    r = client.put("/ai/providers/openai/key", json=body, headers=headers)
    assert r.status_code == 400


def test_delete_removes_a_key(client, _store):
    _store.set_key("gemini", "sk-test-000000000000")
    headers = _auth_headers("DELETE", "/ai/providers/gemini/key")
    r1 = client.request("DELETE", "/ai/providers/gemini/key", headers=headers)
    assert r1.json()["status"] == "deleted"
    assert _store.get_key("gemini") is None

    headers2 = _auth_headers("DELETE", "/ai/providers/gemini/key")
    r2 = client.request("DELETE", "/ai/providers/gemini/key", headers=headers2)
    assert r2.json()["status"] == "not_found"


def test_writes_are_loopback_only(client):
    # Auth is valid; only the loopback gate should reject this. If
    # _require_loopback were removed, this exact request would succeed (200)
    # instead of 404 - so the test is not vacuous.
    body = {"api_key": "sk-test-000000000000"}
    headers = _auth_headers("PUT", "/ai/providers/openai/key", body)
    headers["x-forwarded-for"] = "203.0.113.9"
    r = client.put(
        "/ai/providers/openai/key",
        json=body,
        headers=headers,
    )
    assert r.status_code == 404  # cloaked, not 403


def test_unauthenticated_write_is_rejected(client, _store):
    """Hardening: loopback alone is no longer sufficient for writes - a
    same-machine caller without valid registry auth must be rejected, and
    must not be able to store a key."""
    r = client.put(
        "/ai/providers/openai/key",
        json={"api_key": "sk-test-000000004321"},
    )
    assert r.status_code != 200
    assert r.status_code == 401
    assert _store.get_key("openai") is None
