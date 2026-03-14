"""Tests for the service registry."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from registry.models import HealthStatus, ServiceRegistration
from registry.registry import ServiceRegistry


@pytest.fixture
def registry(tmp_path):
    return ServiceRegistry(persistence_path=str(tmp_path / "registry.json"))


class TestServiceRegistration:
    def test_register_service(self, registry):
        reg = ServiceRegistration(name="test-svc", port=8000)
        record = registry.register(reg)
        assert record.name == "test-svc"
        assert record.port == 8000
        assert record.base_url == "http://localhost:8000"
        assert record.status == HealthStatus.UNKNOWN

    def test_get_service(self, registry):
        registry.register(ServiceRegistration(name="svc1", port=8001))
        record = registry.get("svc1")
        assert record is not None
        assert record.name == "svc1"

    def test_get_nonexistent(self, registry):
        assert registry.get("nonexistent") is None

    def test_get_all(self, registry):
        registry.register(ServiceRegistration(name="a", port=8001))
        registry.register(ServiceRegistration(name="b", port=8002))
        all_services = registry.get_all()
        assert len(all_services) == 2

    def test_deregister(self, registry):
        registry.register(ServiceRegistration(name="svc", port=8000))
        assert registry.deregister("svc")
        assert registry.get("svc") is None

    def test_deregister_nonexistent(self, registry):
        assert not registry.deregister("nope")

    def test_update_registration(self, registry):
        registry.register(ServiceRegistration(name="svc", port=8000))
        registry.register(ServiceRegistration(name="svc", port=9000))
        record = registry.get("svc")
        assert record.port == 9000


class TestHealthUpdates:
    def test_update_health_healthy(self, registry):
        registry.register(ServiceRegistration(name="svc", port=8000))
        record = registry.update_health("svc", HealthStatus.HEALTHY)
        assert record.status == HealthStatus.HEALTHY
        assert record.consecutive_failures == 0

    def test_update_health_unhealthy(self, registry):
        registry.register(ServiceRegistration(name="svc", port=8000))
        registry.update_health("svc", HealthStatus.UNHEALTHY)
        registry.update_health("svc", HealthStatus.UNHEALTHY)
        record = registry.get("svc")
        assert record.consecutive_failures == 2

    def test_update_health_resets_failures(self, registry):
        registry.register(ServiceRegistration(name="svc", port=8000))
        registry.update_health("svc", HealthStatus.UNHEALTHY)
        registry.update_health("svc", HealthStatus.UNHEALTHY)
        registry.update_health("svc", HealthStatus.HEALTHY)
        record = registry.get("svc")
        assert record.consecutive_failures == 0

    def test_update_health_nonexistent(self, registry):
        assert registry.update_health("nope", HealthStatus.HEALTHY) is None


class TestSubscriptions:
    def test_exact_match(self, registry):
        registry.register(ServiceRegistration(
            name="svc", port=8000,
            webhook_url="http://localhost:8000/webhook",
            subscriptions=["security.alert"],
        ))
        subs = registry.get_subscribers("security.alert")
        assert len(subs) == 1

    def test_wildcard_match(self, registry):
        registry.register(ServiceRegistration(
            name="svc", port=8000,
            webhook_url="http://localhost:8000/webhook",
            subscriptions=["security.*"],
        ))
        subs = registry.get_subscribers("security.alert")
        assert len(subs) == 1
        subs = registry.get_subscribers("network.anomaly")
        assert len(subs) == 0

    def test_global_wildcard(self, registry):
        registry.register(ServiceRegistration(
            name="svc", port=8000,
            webhook_url="http://localhost:8000/webhook",
            subscriptions=["*"],
        ))
        assert len(registry.get_subscribers("anything.here")) == 1

    def test_no_webhook_url_excluded(self, registry):
        registry.register(ServiceRegistration(
            name="svc", port=8000,
            subscriptions=["security.*"],
        ))
        assert len(registry.get_subscribers("security.alert")) == 0


class TestPersistence:
    def test_persist_and_load(self, tmp_path):
        path = str(tmp_path / "reg.json")
        reg1 = ServiceRegistry(persistence_path=path)
        reg1.register(ServiceRegistration(name="svc", port=8000))
        reg1.update_health("svc", HealthStatus.HEALTHY)

        reg2 = ServiceRegistry(persistence_path=path)
        record = reg2.get("svc")
        assert record is not None
        assert record.name == "svc"
        assert record.status == HealthStatus.HEALTHY
