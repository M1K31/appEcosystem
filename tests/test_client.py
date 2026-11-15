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
    async def test_register_self_uses_advertise_host(self, monkeypatch):
        """_register_self advertises the topology host (mode-correct), not a raw
        local-IP probe."""
        from ecosystem_client import EcosystemClient
        from ecosystem_client import topology

        monkeypatch.setenv("ECOSYSTEM_MODE", "local")
        client = EcosystemClient(service_name="svc", service_port=8000)
        with patch.object(
            client._discovery, "register_self",
            new_callable=AsyncMock, return_value=True,
        ) as mock_register:
            ok = await client._register_self()

        assert ok is True
        # local mode advertises loopback, and the client records what it used
        assert client._advertised_host == topology.advertise_host() == "127.0.0.1"
        kwargs = mock_register.call_args.kwargs
        assert kwargs["host"] == "127.0.0.1"

    @pytest.mark.asyncio
    async def test_heartbeat_reregisters_on_ip_change(self, monkeypatch):
        """A DHCP/IP change between intervals is pushed to the registry: the
        heartbeat re-registers with the new advertise host."""
        from ecosystem_client import EcosystemClient
        from ecosystem_client.discovery import DiscoveryMode

        client = EcosystemClient(service_name="svc", service_port=8000)
        client._discovery._mode = DiscoveryMode.REGISTRY

        hosts = iter(["10.0.0.5", "10.0.0.9"])  # IP changes on the 2nd call
        monkeypatch.setattr(client, "_current_advertise_host",
                            AsyncMock(side_effect=lambda: next(hosts)))

        with patch.object(
            client._discovery, "register_self",
            new_callable=AsyncMock, return_value=True,
        ) as mock_register:
            await client._register_self()
            assert client._advertised_host == "10.0.0.5"
            await client._register_self()
            assert client._advertised_host == "10.0.0.9"

        assert mock_register.call_count == 2
        assert mock_register.call_args_list[0].kwargs["host"] == "10.0.0.5"
        assert mock_register.call_args_list[1].kwargs["host"] == "10.0.0.9"

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

    @pytest.mark.asyncio
    async def test_registration_401_degrades_to_standalone_and_backs_off(self):
        """On 401 Unauthorized, start() degrades to standalone mode and sets backoff."""
        from ecosystem_client import EcosystemClient
        from ecosystem_client.discovery import DiscoveryMode

        client = EcosystemClient(service_name="test-svc", service_port=8000)
        with patch.object(
            client._discovery, "detect_mode",
            new_callable=AsyncMock, return_value=DiscoveryMode.REGISTRY,
        ):
            # Simulate 401 from discovery
            async def mock_reg_401(*args, **kwargs):
                client._discovery.last_status_code = 401
                client._discovery.is_unauthorized = True
                return False

            with patch.object(client._discovery, "register_self", side_effect=mock_reg_401) as mock_reg:
                with patch.object(client._discovery, "get_peers", new_callable=AsyncMock, return_value={}):
                    await client.start()

            assert client._publisher._mode == DiscoveryMode.STANDALONE
            assert client.is_authenticated is False
            assert client.registration_backoff > 0
            assert client._consecutive_auth_failures == 1

            # Subsequent call during backoff window should skip calling discovery
            with patch.object(client._discovery, "register_self", new_callable=AsyncMock) as mock_reg_subsequent:
                ok = await client._register_self(force=False)
                assert ok is False
                mock_reg_subsequent.assert_not_called()

        await client.stop()

    @pytest.mark.asyncio
    async def test_registration_exponential_backoff_and_reset(self):
        """Repeated 401 errors exponentially increase backoff; reset_backoff clears it."""
        import time
        from ecosystem_client import EcosystemClient
        from ecosystem_client.discovery import DiscoveryMode

        client = EcosystemClient(service_name="test-svc", service_port=8000)
        client._discovery._mode = DiscoveryMode.REGISTRY

        client._discovery.last_status_code = 401
        client._discovery.is_unauthorized = True

        with patch.object(client._discovery, "register_self", new_callable=AsyncMock, return_value=False):
            # Failure 1
            await client._register_self(force=True)
            assert client._consecutive_auth_failures == 1
            # 10s base
            assert 8 < client.registration_backoff <= 10

            # Failure 2
            await client._register_self(force=True)
            assert client._consecutive_auth_failures == 2
            # 20s
            assert 18 < client.registration_backoff <= 20

            # Failure 3
            await client._register_self(force=True)
            assert client._consecutive_auth_failures == 3
            # 40s
            assert 38 < client.registration_backoff <= 40

        # Reset backoff clears backoff and failure count
        client.reset_backoff()
        assert client._consecutive_auth_failures == 0
        assert client.registration_backoff == 0.0
        assert client._discovery.is_unauthorized is False
        assert client.is_authenticated is True

    @pytest.mark.asyncio
    async def test_registration_recovers_to_registry_mode(self):
        """When registration succeeds after failure, registry mode is restored."""
        from ecosystem_client import EcosystemClient
        from ecosystem_client.discovery import DiscoveryMode

        client = EcosystemClient(service_name="test-svc", service_port=8000)
        client._discovery._mode = DiscoveryMode.REGISTRY
        client._consecutive_auth_failures = 3
        client._discovery.is_unauthorized = True

        with patch.object(client._discovery, "register_self", new_callable=AsyncMock, return_value=True):
            ok = await client._register_self(force=True)
            assert ok is True
            assert client._consecutive_auth_failures == 0
            assert client._discovery.is_unauthorized is False
            assert client.is_authenticated is True

    @pytest.mark.asyncio
    async def test_unauthorized_discovery_skips_services_fetch(self):
        """When discovery is marked unauthorized, _fetch_registry_services skips requests."""
        from ecosystem_client.discovery import DiscoveryManager, EcosystemConfig

        cfg = EcosystemConfig.from_env()
        dm = DiscoveryManager(cfg)
        dm.is_unauthorized = True

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            services = await dm._fetch_registry_services()
            assert services == []
            mock_get.assert_not_called()
