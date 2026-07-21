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
