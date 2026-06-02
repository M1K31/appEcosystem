"""Tests for CommandRouter harness-preference routing cascade."""

from unittest.mock import AsyncMock, patch, MagicMock
import pytest

from llm.command_router import CommandRouter


@pytest.fixture
def router():
    """Router with mocked discovery (no real registry)."""
    discovery = MagicMock()
    discovery.discover_all = AsyncMock(return_value=[])
    return CommandRouter(discovery=discovery)


class TestHarnessAvailability:
    """Tests for _harness_available() caching."""

    @pytest.mark.asyncio
    async def test_harness_available_when_daemon_responds(self, router):
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_resp = MagicMock(status_code=200)
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await router._harness_available()
            assert result is True

    @pytest.mark.asyncio
    async def test_harness_unavailable_on_connection_error(self, router):
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=ConnectionError("refused"))
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await router._harness_available()
            assert result is False

    @pytest.mark.asyncio
    async def test_harness_cache_reuses_result(self, router):
        """Second call within TTL should not make a new HTTP request."""
        router._harness_ok = True
        router._harness_checked_at = __import__("time").monotonic()

        # Should return cached True without any HTTP call
        result = await router._harness_available()
        assert result is True


class TestRoutingCascade:
    """Tests for route() harness-first, fallback-to-direct cascade."""

    @pytest.mark.asyncio
    async def test_security_capability_routes_via_harness(self, router):
        """Security capabilities should try harness first."""
        router._harness_available = AsyncMock(return_value=True)
        router._route_via_harness = AsyncMock(return_value={
            "status": "ok",
            "data": {"result": "threat analysis complete"},
            "source": "harness",
        })

        result = await router.route("asusguard", "threat_analysis", body={"ip": "1.2.3.4"})

        assert result["status"] == "ok"
        assert result["source"] == "harness"
        router._route_via_harness.assert_called_once()

    @pytest.mark.asyncio
    async def test_non_security_capability_skips_harness(self, router):
        """Non-security capabilities should never try harness."""
        router._harness_available = AsyncMock(return_value=True)
        router._route_via_harness = AsyncMock()

        # "camera_monitoring" is not in _HARNESS_CAPABILITIES
        result = await router.route("openeye", "camera_monitoring")

        router._route_via_harness.assert_not_called()
        # Should fall through to manifest lookup (returns error since no manifests)
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_harness_failure_falls_back_to_direct(self, router):
        """If harness returns error, should fall back to manifest-based routing."""
        router._harness_available = AsyncMock(return_value=True)
        router._route_via_harness = AsyncMock(return_value={
            "status": "error",
            "detail": "harness unavailable",
        })

        result = await router.route("asusguard", "threat_analysis", body={"ip": "1.2.3.4"})

        # Falls through to manifest lookup (no manifests loaded → error)
        assert result["status"] == "error"
        assert "Unknown project" in result.get("detail", "")

    @pytest.mark.asyncio
    async def test_harness_unavailable_skips_to_direct(self, router):
        """If harness is down, should go straight to manifest routing."""
        router._harness_available = AsyncMock(return_value=False)
        router._route_via_harness = AsyncMock()

        result = await router.route("asusguard", "security_scan")

        router._route_via_harness.assert_not_called()

    @pytest.mark.asyncio
    async def test_all_harness_capabilities_recognized(self, router):
        """All 6 harness capabilities should trigger harness routing."""
        expected = {"threat_analysis", "log_analysis", "security_scan",
                    "incident_triage", "block_ip", "security_status"}
        assert router._HARNESS_CAPABILITIES == expected


class TestRouteViaHarness:
    """Tests for _route_via_harness() HTTP call."""

    @pytest.mark.asyncio
    async def test_posts_to_analyze_endpoint(self, router):
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_resp = MagicMock(status_code=200)
            mock_resp.json.return_value = {"result": "analysis done", "model": "llama3"}
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await router._route_via_harness("asusguard", "threat_analysis", {"ip": "1.2.3.4"})

            assert result["status"] == "ok"
            assert result["source"] == "harness"
            # Verify correct URL and payload
            call_args = mock_client.post.call_args
            assert "/api/analyze" in call_args[0][0]
            payload = call_args[1]["json"]
            assert payload["project"] == "asusguard"
            assert payload["capability"] == "threat_analysis"
            assert payload["ip"] == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_returns_error_on_non_200(self, router):
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_resp = MagicMock(status_code=502)
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await router._route_via_harness("asusguard", "log_analysis", {})

            assert result["status"] == "error"
