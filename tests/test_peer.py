from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from ecosystem_client.peer import Peer


class TestPeer:
    def test_peer_creation(self):
        peer = Peer(name="openeye", base_url="http://192.168.1.20:8200", hmac_secret="secret")
        assert peer.name == "openeye"
        assert peer.base_url == "http://192.168.1.20:8200"

    @pytest.mark.asyncio
    async def test_peer_get(self):
        peer = Peer(name="openeye", base_url="http://192.168.1.20:8200", hmac_secret="secret")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"cameras": []}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient.request", new_callable=AsyncMock, return_value=mock_response):
            result = await peer.get("/api/cameras")

        assert result == {"cameras": []}

    @pytest.mark.asyncio
    async def test_peer_post(self):
        peer = Peer(name="ai", base_url="http://192.168.1.20:8000", hmac_secret="secret")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok"}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient.request", new_callable=AsyncMock, return_value=mock_response):
            result = await peer.post("/api/v1/chat", json={"message": "hello"})

        assert result == {"status": "ok"}

    @pytest.mark.asyncio
    async def test_peer_unavailable_returns_none(self):
        peer = Peer(name="openeye", base_url="http://192.168.1.20:8200", hmac_secret="secret")

        with patch("httpx.AsyncClient.request", new_callable=AsyncMock, side_effect=Exception("Connection refused")):
            result = await peer.get("/api/cameras")

        assert result is None
        assert peer.is_degraded

    def test_peer_health_status_tracking(self):
        peer = Peer(name="openeye", base_url="http://localhost:8200", hmac_secret="s")
        assert not peer.is_degraded
        peer.mark_degraded()
        assert peer.is_degraded
        peer.mark_healthy()
        assert not peer.is_degraded
