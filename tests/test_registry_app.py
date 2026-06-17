"""Endpoint tests for the registry FastAPI app (app.state wiring)."""

import sys
import time
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "auth" / "python"))

from registry.app import app, get_registry
from ecosystem_auth.tokens import sign_request

TEST_SECRET = "registry-app-test-secret"


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Isolate persistence and skip loading the real ecosystem.yaml.
    monkeypatch.setenv("ECOSYSTEM_REGISTRY_FILE", str(tmp_path / "registry.json"))
    monkeypatch.setenv("ECOSYSTEM_CONFIG", str(tmp_path / "missing.yaml"))
    monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", TEST_SECRET)
    # Reset the process-wide nonce store between tests.
    from auth.python.ecosystem_auth import middleware
    middleware._nonce_store._seen.clear()
    with TestClient(app) as c:
        yield c


class TestRegistryEndpoints:
    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_services_empty_after_startup(self, client):
        resp = client.get("/services")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_register_requires_auth(self, client):
        resp = client.post("/register", json={"name": "x", "port": 8000})
        assert resp.status_code == 401

    def test_get_unknown_service_404(self, client):
        resp = client.get("/services/nope")
        assert resp.status_code == 404

    def test_metrics_endpoint(self, client):
        resp = client.get("/metrics")
        assert resp.status_code == 200
        body = resp.text
        assert "ecosystem_registry_up 1" in body
        assert "ecosystem_health_checks_total" in body
        assert 'ecosystem_services{status="' in body


class TestReplayProtection:
    REG_URL = "http://testserver/register"

    def _payload(self):
        return {"name": "svc-a", "port": 8000}

    def test_valid_signed_register_succeeds(self, client):
        body = self._payload()
        headers = sign_request("POST", self.REG_URL, TEST_SECRET, body)
        resp = client.post("/register", json=body, headers=headers)
        assert resp.status_code == 201
        assert resp.json()["name"] == "svc-a"

    def test_replayed_request_rejected(self, client):
        body = self._payload()
        headers = sign_request("POST", self.REG_URL, TEST_SECRET, body)
        first = client.post("/register", json=body, headers=headers)
        assert first.status_code == 201
        # Same signature + nonce replayed
        replay = client.post("/register", json=body, headers=headers)
        assert replay.status_code == 401

    def test_stale_timestamp_rejected(self, client):
        body = self._payload()
        old_ts = int(time.time()) - 1000
        headers = sign_request("POST", self.REG_URL, TEST_SECRET, body, ts=old_ts)
        resp = client.post("/register", json=body, headers=headers)
        assert resp.status_code == 401

    def test_tampered_body_rejected(self, client):
        body = self._payload()
        headers = sign_request("POST", self.REG_URL, TEST_SECRET, body)
        tampered = {"name": "svc-a", "port": 9999}
        resp = client.post("/register", json=tampered, headers=headers)
        assert resp.status_code == 401

    def test_wrong_secret_rejected(self, client):
        body = self._payload()
        headers = sign_request("POST", self.REG_URL, "wrong-secret", body)
        resp = client.post("/register", json=body, headers=headers)
        assert resp.status_code == 401


class TestDependencyGuards:
    def test_get_registry_503_when_uninitialized(self):
        class _State:
            pass

        class _App:
            state = _State()

        class _Req:
            app = _App()

        with pytest.raises(HTTPException) as exc:
            get_registry(_Req())
        assert exc.value.status_code == 503
