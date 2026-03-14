from unittest.mock import AsyncMock, patch

import pytest


class TestEcosystemClient:
    @pytest.mark.asyncio
    async def test_start_detects_mode(self):
        from ecosystem_client import EcosystemClient
        from ecosystem_client.discovery import DiscoveryMode

        client = EcosystemClient(
            service_name="test-svc",
            service_port=8000,
        )
        with patch.object(
            client._discovery, "detect_mode",
            new_callable=AsyncMock, return_value=DiscoveryMode.STANDALONE,
        ):
            await client.start()

        assert client.mode == DiscoveryMode.STANDALONE

    @pytest.mark.asyncio
    async def test_start_registers_in_mode1(self):
        from ecosystem_client import EcosystemClient
        from ecosystem_client.discovery import DiscoveryMode

        client = EcosystemClient(
            service_name="test-svc",
            service_port=8000,
        )
        with patch.object(
            client._discovery, "detect_mode",
            new_callable=AsyncMock, return_value=DiscoveryMode.REGISTRY,
        ):
            with patch.object(
                client._discovery, "register_self",
                new_callable=AsyncMock, return_value=True,
            ) as mock_register:
                with patch.object(
                    client._discovery, "get_peers",
                    new_callable=AsyncMock, return_value={},
                ):
                    await client.start()

        mock_register.assert_called_once()

    @pytest.mark.asyncio
    async def test_discover_returns_peer(self):
        from ecosystem_client import EcosystemClient
        from ecosystem_client.discovery import DiscoveryMode

        client = EcosystemClient(
            service_name="magicmirror",
            service_port=8080,
        )
        client._discovery._mode = DiscoveryMode.PEER_TO_PEER
        client._peers = {
            "openeye": {"name": "openeye", "base_url": "http://192.168.1.20:8200"},
        }
        client._started = True

        peer = await client.discover("openeye")
        assert peer is not None
        assert peer.name == "openeye"

    @pytest.mark.asyncio
    async def test_discover_returns_none_when_not_found(self):
        from ecosystem_client import EcosystemClient
        from ecosystem_client.discovery import DiscoveryMode

        client = EcosystemClient(
            service_name="magicmirror",
            service_port=8080,
        )
        client._discovery._mode = DiscoveryMode.STANDALONE
        client._started = True

        peer = await client.discover("nonexistent")
        assert peer is None

    @pytest.mark.asyncio
    async def test_publish_delegates_to_publisher(self):
        from ecosystem_client import EcosystemClient

        client = EcosystemClient(service_name="openeye", service_port=8200)
        client._started = True

        with patch.object(
            client._publisher, "publish",
            new_callable=AsyncMock, return_value={"delivered": 1},
        ) as mock_pub:
            result = await client.publish("security.alert", {"camera_id": 1})

        mock_pub.assert_called_once_with("security.alert", {"camera_id": 1})
        assert result["delivered"] == 1

    def test_on_registers_handler(self):
        from ecosystem_client import EcosystemClient

        client = EcosystemClient(service_name="mm", service_port=8080)

        @client.on("security.alert")
        async def handler(event):
            pass

        assert "security.alert" in client._subscriber._handlers

    @pytest.mark.asyncio
    async def test_stop_deregisters(self):
        from ecosystem_client import EcosystemClient
        from ecosystem_client.discovery import DiscoveryMode

        client = EcosystemClient(service_name="test-svc", service_port=8000)
        client._discovery._mode = DiscoveryMode.REGISTRY
        client._started = True

        with patch.object(
            client._discovery, "deregister_self",
            new_callable=AsyncMock, return_value=True,
        ) as mock_dereg:
            await client.stop()

        mock_dereg.assert_called_once_with("test-svc")
