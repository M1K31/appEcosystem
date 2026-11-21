"""Self-service third-party registration (approval-gated) and first-party keys, over HTTP."""
import pytest
from fastapi.testclient import TestClient

from registry.app import app
from registry.app_store import AppStore
from ecosystem_auth.tokens import sign_request

OWNER_SECRET = "owner-shared-secret-value-abcdef0123456789"


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
    return {"apps_file": str(apps_file), "store": AppStore(persistence_path=str(apps_file))}


def _owner(method, path, body=None):
    return sign_request(method, f"http://testserver{path}", OWNER_SECRET, body)


# ---- self-registration is open but inert --------------------------------------------


def test_register_is_open_and_returns_a_pending_key(env):
    with TestClient(app) as client:
        r = client.post("/apps/register", json={"app_id": "org.widget", "display_name": "Widget",
                                                "requested_names": ["widget_sensor"],
                                                "requested_scopes": ["commands:dispatch"]})
        assert r.status_code == 201
        data = r.json()
        assert data["status"] == "pending" and data["secret"] and data["key_id"]

        # The pending key authenticates nothing: a signed command-dispatch is 401.
        body = {"name": "widget_sensor", "port": 9000, "host": "localhost"}
        headers = sign_request("POST", "http://testserver/register", data["secret"], body, key_id=data["key_id"])
        assert client.post("/register", json=body, headers=headers).status_code == 401


def test_register_will_not_overwrite_an_existing_app(env):
    env["store"].add("org.widget", "Widget", "o", ["widget_sensor"])
    with TestClient(app) as client:
        r = client.post("/apps/register", json={"app_id": "org.widget"})
        assert r.status_code == 409


def test_register_requires_an_app_id(env):
    with TestClient(app) as client:
        assert client.post("/apps/register", json={}).status_code == 422


# ---- approval is owner-only and activates the key -----------------------------------


def test_owner_approves_and_the_key_then_works(env):
    with TestClient(app) as client:
        reg = client.post("/apps/register", json={"app_id": "org.widget", "requested_names": ["widget_sensor"]}).json()

        # A non-owner (the pending app's own key) cannot approve itself.
        forged = client.post(f"/apps/org.widget/approve", json={"owned_names": ["widget_sensor"], "scopes": ["*"]},
                             headers=sign_request("POST", "http://testserver/apps/org.widget/approve",
                                                   reg["secret"], {"owned_names": ["widget_sensor"], "scopes": ["*"]},
                                                   key_id=reg["key_id"]))
        assert forged.status_code in (401, 403)

        body = {"owned_names": ["widget_sensor"], "scopes": ["commands:dispatch", "commands:read"]}
        ok = client.post("/apps/org.widget/approve", json=body,
                         headers=_owner("POST", "/apps/org.widget/approve", body))
        assert ok.status_code == 200 and ok.json()["status"] == "approved"

        # Now the app's key authenticates for its own name.
        reg_body = {"name": "widget_sensor", "port": 9000, "host": "localhost"}
        headers = sign_request("POST", "http://testserver/register", reg["secret"], reg_body, key_id=reg["key_id"])
        assert client.post("/register", json=reg_body, headers=headers).status_code == 201


def test_owner_rejects_a_pending_registration(env):
    with TestClient(app) as client:
        client.post("/apps/register", json={"app_id": "org.spam"})
        r = client.post("/apps/org.spam/reject", headers=_owner("POST", "/apps/org.spam/reject"))
        assert r.status_code == 200
        # Gone: a second reject is 404.
        assert client.post("/apps/org.spam/reject", headers=_owner("POST", "/apps/org.spam/reject")).status_code == 404


def test_approve_refuses_a_reserved_name_for_a_third_party(env):
    with TestClient(app) as client:
        client.post("/apps/register", json={"app_id": "org.evil", "requested_names": ["openeye"]})
        body = {"owned_names": ["openeye"], "scopes": []}
        r = client.post("/apps/org.evil/approve", json=body, headers=_owner("POST", "/apps/org.evil/approve", body))
        assert r.status_code == 400


def test_list_and_approve_need_owner_auth(env):
    with TestClient(app) as client:
        assert client.get("/apps").status_code == 401
        assert client.post("/apps/x/approve", json={}).status_code == 401
        listed = client.get("/apps", headers=_owner("GET", "/apps"))
        assert listed.status_code == 200 and "apps" in listed.json()


# ---- first-party key may own its reserved name --------------------------------------


def test_first_party_app_can_hold_its_reserved_name(env):
    with TestClient(app) as client:
        client.post("/apps/register", json={"app_id": "aegissiem.node1", "requested_names": ["aegissiem"]})
        body = {"owned_names": ["aegissiem"], "scopes": ["*"], "first_party": True}
        r = client.post("/apps/aegissiem.node1/approve", json=body,
                        headers=_owner("POST", "/apps/aegissiem.node1/approve", body))
        assert r.status_code == 200 and r.json()["first_party"] is True
        assert r.json()["owned_names"] == ["aegissiem"]


def test_an_approved_non_owner_app_still_cannot_approve_others(env):
    # An authenticated partner key (not the owner) must get 403 from require_owner,
    # not merely 401 for missing auth.
    rec, secret = env["store"].add("org.partner", "Partner", "o", ["partner_svc"],
                                   scopes=["commands:dispatch"])
    with TestClient(app) as client:
        client.post("/apps/register", json={"app_id": "org.target", "requested_names": ["target_svc"]})
        body = {"owned_names": ["target_svc"], "scopes": ["*"]}
        headers = sign_request("POST", "http://testserver/apps/org.target/approve", secret, body,
                               key_id=rec["key_id"])
        r = client.post("/apps/org.target/approve", json=body, headers=headers)
        assert r.status_code == 403
        assert env["store"].get("org.target")["status"] == "pending"  # unchanged
        # The owner listing is likewise forbidden to the partner key.
        assert client.get("/apps", headers=sign_request("GET", "http://testserver/apps", secret,
                                                        key_id=rec["key_id"])).status_code == 403


def test_cannot_self_register_as_the_owner(env):
    with TestClient(app) as client:
        r = client.post("/apps/register", json={"app_id": "__owner__"})
        assert r.status_code == 422
        assert env["store"].get("__owner__") is None


def test_owner_cannot_approve_a_wildcard_name(env):
    with TestClient(app) as client:
        client.post("/apps/register", json={"app_id": "org.greedy", "requested_names": ["x"]})
        body = {"owned_names": ["*"], "scopes": ["commands:dispatch"]}
        r = client.post("/apps/org.greedy/approve", json=body,
                        headers=_owner("POST", "/apps/org.greedy/approve", body))
        assert r.status_code == 400
        assert env["store"].get("org.greedy")["status"] == "pending"


def test_first_party_must_be_a_real_boolean(env):
    with TestClient(app) as client:
        client.post("/apps/register", json={"app_id": "org.sneaky", "requested_names": ["openeye"]})
        body = {"owned_names": ["openeye"], "scopes": [], "first_party": "false"}
        r = client.post("/apps/org.sneaky/approve", json=body,
                        headers=_owner("POST", "/apps/org.sneaky/approve", body))
        assert r.status_code == 422
        assert env["store"].get("org.sneaky")["status"] == "pending"


def test_a_bearer_token_has_no_owner_access(env):
    # A valid service bearer token is authenticated but is NOT the owner: owner-only
    # routes return 403 (not 401), while the shared-secret HMAC owner gets through.
    import json
    from ecosystem_auth.tokens import create_ecosystem_token
    token = json.dumps(create_ecosystem_token(OWNER_SECRET, "openeye"))
    with TestClient(app) as client:
        bearer = {"Authorization": f"Bearer {token}"}
        assert client.get("/apps", headers=bearer).status_code == 403
        assert client.post("/apps/x/approve", json={}, headers=bearer).status_code == 403
        assert client.get("/apps", headers=_owner("GET", "/apps")).status_code == 200
