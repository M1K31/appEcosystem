from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from ecosystem_client.config import EcosystemConfig
from ecosystem_client.discovery import DiscoveryMode


class TestEventPublisher:
    @pytest.mark.asyncio
    async def test_publish_mode1_delegates_to_bus(self):
        from ecosystem_client.event_publisher import EventPublisher

        config = EcosystemConfig(hmac_secret="test-secret")
        pub = EventPublisher(config, mode=DiscoveryMode.REGISTRY, service_name="openeye")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"delivered": 1, "failed": 0}

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            result = await pub.publish("security.alert", {"camera_id": 1})

        assert result["delivered"] == 1

    @pytest.mark.asyncio
    async def test_publish_mode2_sends_to_peers(self):
        from ecosystem_client.event_publisher import EventPublisher

        config = EcosystemConfig(hmac_secret="test-secret")
        pub = EventPublisher(config, mode=DiscoveryMode.PEER_TO_PEER, service_name="openeye")
        pub.set_peer_webhooks({
            "magicmirror": {
                "webhook_url": "http://192.168.1.10:8080/ecosystem/events",
                "subscriptions": ["security.*"],
            },
        })

        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            result = await pub.publish("security.alert", {"camera_id": 1})

        assert result["delivered"] == 1

    @pytest.mark.asyncio
    async def test_publish_mode3_noop(self):
        from ecosystem_client.event_publisher import EventPublisher

        config = EcosystemConfig(hmac_secret="test-secret")
        pub = EventPublisher(config, mode=DiscoveryMode.STANDALONE, service_name="openeye")

        result = await pub.publish("security.alert", {"camera_id": 1})
        assert result["delivered"] == 0
        assert result["mode"] == "standalone"

    @pytest.mark.asyncio
    async def test_publish_matches_wildcard_subscriptions(self):
        from ecosystem_client.event_publisher import EventPublisher

        config = EcosystemConfig(hmac_secret="test-secret")
        pub = EventPublisher(config, mode=DiscoveryMode.PEER_TO_PEER, service_name="openeye")
        pub.set_peer_webhooks({
            "mm": {
                "webhook_url": "http://192.168.1.10:8080/ecosystem/events",
                "subscriptions": ["security.*"],
            },
            "ai": {
                "webhook_url": "http://192.168.1.20:8000/ecosystem/events",
                "subscriptions": ["network.*"],
            },
        })

        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            result = await pub.publish("security.alert", {})

        # Only magicmirror should match security.*
        assert result["delivered"] == 1
        assert result["subscribers"] == ["mm"]
