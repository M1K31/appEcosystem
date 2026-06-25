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
    monkeypatch.setenv("ECOSYSTEM_AI_PROFILE_FILE", str(tmp_path / "ai_profile.json"))
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


class TestStaticSubsetTolerance:
    """Static pre-registration only includes locally-present apps (subset/
    multi-device tolerance) unless ECOSYSTEM_REGISTER_ALL_STATIC forces all."""

    def _write_config(self, tmp_path):
        import yaml
        # base/ is the sibling-repo root (config lives at base/repo/ecosystem.yaml).
        base = tmp_path / "base"
        repo = base / "repo"
        repo.mkdir(parents=True)
        (base / "present_app").mkdir()  # installed locally
        # absent_app dir intentionally not created
        cfg = {
            "ecosystem": {"base_path": str(base)},
            "projects": {
                "present_app": {"path": "present_app", "port": 9001,
                                "health_endpoint": "/health"},
                "absent_app": {"path": "absent_app", "port": 9002,
                               "health_endpoint": "/health"},
            },
        }
        cfg_path = repo / "ecosystem.yaml"
        cfg_path.write_text(yaml.safe_dump(cfg))
        return cfg_path

    def test_skips_apps_not_installed_locally(self, tmp_path, monkeypatch):
        from registry.app import _register_static_projects
        from registry.registry import ServiceRegistry

        cfg_path = self._write_config(tmp_path)
        monkeypatch.setenv("ECOSYSTEM_CONFIG", str(cfg_path))
        monkeypatch.delenv("ECOSYSTEM_REGISTER_ALL_STATIC", raising=False)

        reg = ServiceRegistry(persistence_path=str(tmp_path / "reg.json"))
        _register_static_projects(reg)

        names = {s.name for s in reg.get_all()}
        assert "present_app" in names
        assert "absent_app" not in names  # not installed here -> not pre-registered

    def test_register_all_override_includes_absent(self, tmp_path, monkeypatch):
        from registry.app import _register_static_projects
        from registry.registry import ServiceRegistry

        cfg_path = self._write_config(tmp_path)
        monkeypatch.setenv("ECOSYSTEM_CONFIG", str(cfg_path))
        monkeypatch.setenv("ECOSYSTEM_REGISTER_ALL_STATIC", "1")

        reg = ServiceRegistry(persistence_path=str(tmp_path / "reg.json"))
        _register_static_projects(reg)

        names = {s.name for s in reg.get_all()}
        assert {"present_app", "absent_app"} <= names


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


class TestAIProfileSync:
    PROFILE_URL = "http://testserver/ai-profile"

    def test_get_default_is_ollama(self, client):
        resp = client.get("/ai-profile")
        assert resp.status_code == 200
        body = resp.json()
        assert body["default_provider"] == "ollama"
        assert body["selected_model"] == "auto"
        assert body["version"] >= 1

    def test_put_requires_auth(self, client):
        resp = client.put("/ai-profile", json={"selected_model": "llama3.1:8b"})
        assert resp.status_code == 401

    def test_put_updates_and_bumps_version(self, client):
        before = client.get("/ai-profile").json()["version"]
        changes = {"selected_model": "llama3.1:8b"}
        headers = sign_request("PUT", self.PROFILE_URL, TEST_SECRET, changes)
        resp = client.put("/ai-profile", json=changes, headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["selected_model"] == "llama3.1:8b"
        assert body["version"] == before + 1
        # The change is now visible to every other reader (the sync behavior).
        assert client.get("/ai-profile").json()["selected_model"] == "llama3.1:8b"

    def test_put_ignores_non_writable_fields(self, client):
        changes = {"version": 999, "selected_model": "mistral:7b"}
        headers = sign_request("PUT", self.PROFILE_URL, TEST_SECRET, changes)
        body = client.put("/ai-profile", json=changes, headers=headers).json()
        assert body["selected_model"] == "mistral:7b"
        assert body["version"] != 999  # version is server-managed


class TestAIPlacement:
    def test_empty_when_no_resources(self, client):
        assert client.get("/ai-placement").json() is None

    def test_recommends_reporting_host(self, client):
        reg = {
            "name": "workstation", "host": "127.0.0.1", "port": 8400,
            "resources": {"tier": 3, "ram_gb": 32, "vram_gb": 16, "has_gpu": True},
        }
        headers = sign_request("POST", "http://testserver/register", TEST_SECRET, reg)
        assert client.post("/register", json=reg, headers=headers).status_code == 201
        best = client.get("/ai-placement").json()
        assert best is not None
        assert best["name"] == "workstation"
        assert best["resources"]["tier"] == 3


class TestReadAuth:
    def test_read_open_by_default(self, client):
        assert client.get("/services").status_code == 200

    def test_read_requires_auth_when_enabled(self, client, monkeypatch):
        monkeypatch.setenv("ECOSYSTEM_REQUIRE_READ_AUTH", "true")
        # Unsigned read is rejected.
        assert client.get("/services").status_code == 401
        # Signed read succeeds.
        headers = sign_request("GET", "http://testserver/services", TEST_SECRET)
        assert client.get("/services", headers=headers).status_code == 200


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
