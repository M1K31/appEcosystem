"""Tests for the health monitor."""

import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from registry.health_monitor import HealthMonitor
from registry.models import HealthStatus, ServiceRegistration
from registry.registry import ServiceRegistry


@pytest.fixture
def registry():
    reg = ServiceRegistry()
    reg.register(ServiceRegistration(name="test-svc", port=9999, health_endpoint="/health"))
    return reg


@pytest.fixture
def monitor(registry):
    return HealthMonitor(registry=registry, interval_seconds=5, timeout_seconds=2)


class TestHealthMonitor:
    @pytest.mark.asyncio
    async def test_check_one_healthy(self, monitor):
        mock_response = AsyncMock()
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        monitor._client = mock_client

        result = await monitor.check_one("test-svc")
        assert result.status == HealthStatus.HEALTHY
        assert result.response_time_ms is not None

    @pytest.mark.asyncio
    async def test_check_one_connection_error(self, monitor):
        import httpx

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        monitor._client = mock_client

        result = await monitor.check_one("test-svc")
        assert result.status == HealthStatus.UNHEALTHY
        assert "Connection refused" in result.detail

    @pytest.mark.asyncio
    async def test_check_one_unknown_service(self, monitor):
        result = await monitor.check_one("nonexistent")
        assert result.status == HealthStatus.UNKNOWN

    @pytest.mark.asyncio
    async def test_check_all(self, monitor):
        mock_response = AsyncMock()
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        monitor._client = mock_client

        results = await monitor.check_all()
        assert len(results) == 1
        assert results[0].service_name == "test-svc"


class TestFailureThresholds:
    @pytest.mark.asyncio
    async def test_dynamic_service_deregistered(self):
        from registry.models import HealthCheckResult

        reg = ServiceRegistry()
        reg.register(ServiceRegistration(name="dyn", port=9001))
        mon = HealthMonitor(registry=reg, max_failures=3)

        reg.get("dyn").consecutive_failures = 3
        result = HealthCheckResult(service_name="dyn", status=HealthStatus.UNHEALTHY)
        await mon._handle_failure_thresholds([result])

        assert reg.get("dyn") is None  # removed

    @pytest.mark.asyncio
    async def test_static_service_retained(self):
        from registry.models import HealthCheckResult

        reg = ServiceRegistry()
        reg.register(ServiceRegistration(name="stat", port=9002, static=True))
        mon = HealthMonitor(registry=reg, max_failures=3)

        reg.get("stat").consecutive_failures = 5
        result = HealthCheckResult(service_name="stat", status=HealthStatus.UNHEALTHY)
        await mon._handle_failure_thresholds([result])

        assert reg.get("stat") is not None  # retained for recovery
