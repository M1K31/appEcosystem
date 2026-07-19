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
        r = _post_register(client, "openeye", OWNER_SECRET)
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
