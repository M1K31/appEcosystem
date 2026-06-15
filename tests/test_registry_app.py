"""Endpoint tests for the registry FastAPI app (app.state wiring)."""

import sys
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))

from registry.app import app, get_registry


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Isolate persistence and skip loading the real ecosystem.yaml.
    monkeypatch.setenv("ECOSYSTEM_REGISTRY_FILE", str(tmp_path / "registry.json"))
    monkeypatch.setenv("ECOSYSTEM_CONFIG", str(tmp_path / "missing.yaml"))
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
