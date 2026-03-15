from unittest.mock import AsyncMock, patch

import pytest

from ecosystem_client.config import EcosystemConfig


class TestDiscoveryMode:
    """Test the three-mode discovery cascade."""

    @pytest.mark.asyncio
    async def test_mode1_registry_available(self):
        from ecosystem_client.discovery import DiscoveryManager, DiscoveryMode

        config = EcosystemConfig(registry_url="http://localhost:8500")
        dm = DiscoveryManager(config)

        with patch.object(dm, "_check_registry", new_callable=AsyncMock, return_value=True):
            mode = await dm.detect_mode()

        assert mode == DiscoveryMode.REGISTRY

    @pytest.mark.asyncio
    async def test_mode2_mdns_fallback(self):
        from ecosystem_client.discovery import DiscoveryManager, DiscoveryMode

        config = EcosystemConfig(registry_url="http://localhost:8500")
        dm = DiscoveryManager(config)

        with patch.object(dm, "_check_registry", new_callable=AsyncMock, return_value=False):
            with patch.object(dm, "_check_mdns", return_value=[
                {"name": "openeye", "host": "192.168.1.20", "port": 8200}
            ]):
                mode = await dm.detect_mode()

        assert mode == DiscoveryMode.PEER_TO_PEER

    @pytest.mark.asyncio
    async def test_mode2_static_peers_fallback(self):
        from ecosystem_client.discovery import DiscoveryManager, DiscoveryMode

        config = EcosystemConfig(
            registry_url="http://localhost:8500",
            peers={"openeye": "http://192.168.1.20:8200"},
        )
        dm = DiscoveryManager(config)

        with patch.object(dm, "_check_registry", new_callable=AsyncMock, return_value=False):
            with patch.object(dm, "_check_mdns", return_value=[]):
                mode = await dm.detect_mode()

        assert mode == DiscoveryMode.PEER_TO_PEER

    @pytest.mark.asyncio
    async def test_mode3_standalone(self):
        from ecosystem_client.discovery import DiscoveryManager, DiscoveryMode

        config = EcosystemConfig(registry_url="http://localhost:8500", peers={})
        dm = DiscoveryManager(config)

        with patch.object(dm, "_check_registry", new_callable=AsyncMock, return_value=False):
            with patch.object(dm, "_check_mdns", return_value=[]):
                mode = await dm.detect_mode()

        assert mode == DiscoveryMode.STANDALONE

    @pytest.mark.asyncio
    async def test_disabled_forces_standalone(self):
        from ecosystem_client.discovery import DiscoveryManager, DiscoveryMode

        config = EcosystemConfig(enabled=False)
        dm = DiscoveryManager(config)
        mode = await dm.detect_mode()
        assert mode == DiscoveryMode.STANDALONE

    @pytest.mark.asyncio
    async def test_get_peers_from_registry(self):
        from ecosystem_client.discovery import DiscoveryManager, DiscoveryMode

        config = EcosystemConfig(registry_url="http://localhost:8500")
        dm = DiscoveryManager(config)
        dm._mode = DiscoveryMode.REGISTRY

        mock_services = [
            {"name": "openeye", "base_url": "http://192.168.1.20:8200",
             "health_endpoint": "/api/ecosystem/health",
             "webhook_url": "http://192.168.1.20:8200/ecosystem/events",
             "subscriptions": ["security.*"]},
        ]
        with patch.object(dm, "_fetch_registry_services", new_callable=AsyncMock, return_value=mock_services):
            peers = await dm.get_peers()

        assert "openeye" in peers
        assert peers["openeye"]["base_url"] == "http://192.168.1.20:8200"

    @pytest.mark.asyncio
    async def test_get_peers_from_static(self):
        from ecosystem_client.discovery import DiscoveryManager, DiscoveryMode

        config = EcosystemConfig(
            peers={"openeye": "http://192.168.1.20:8200"},
        )
        dm = DiscoveryManager(config)
        dm._mode = DiscoveryMode.PEER_TO_PEER

        peers = await dm.get_peers()
        assert "openeye" in peers

    @pytest.mark.asyncio
    async def test_get_peers_standalone_returns_empty(self):
        from ecosystem_client.discovery import DiscoveryManager, DiscoveryMode

        config = EcosystemConfig()
        dm = DiscoveryManager(config)
        dm._mode = DiscoveryMode.STANDALONE

        peers = await dm.get_peers()
        assert peers == {}
