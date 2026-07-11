"""Per-app key resolver path in ecosystem_auth.middleware."""
import json
import pytest
from starlette.requests import Request

from ecosystem_auth import middleware
from ecosystem_auth.tokens import sign_request, KEY_ID_HEADER


def _asgi_request(method, url, headers: dict, body: bytes = b""):
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    scope = {
        "type": "http", "method": method, "headers": raw,
        "path": parts.path, "query_string": b"",
        "server": (parts.hostname or "testserver", parts.port or 80),
        "scheme": parts.scheme or "http",
    }

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
    headers = sign_request("POST", url, "wrong-secret", body, key_id="k_acme")
    req = _asgi_request("POST", url, headers, json.dumps(body).encode())
    from fastapi import HTTPException
    resolver = lambda k: {"secret": "the-real-secret", "app_id": "org.acme",
                          "scopes": [], "owned_names": ["acme_thermostat"]}
    with pytest.raises(HTTPException) as exc:
        await middleware.authenticate_request(req, None, key_resolver=resolver)
    assert exc.value.status_code == 401
