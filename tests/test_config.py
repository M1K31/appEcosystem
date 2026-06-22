import pytest

from ecosystem_client.config import EcosystemConfig


class TestEcosystemConfig:
    def test_default_values(self):
        config = EcosystemConfig()
        assert config.registry_url == "http://localhost:8500"
        # Fail-closed: no default secret (a committed default would be forgeable).
        assert config.hmac_secret == ""
        assert config.service_name is None
        assert config.service_port is None
        assert config.health_endpoint == "/health"
        assert config.enabled is True
        assert config.discovery_interval == 60
        assert config.peers == {}

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("ECOSYSTEM_REGISTRY_URL", "http://10.0.0.1:8500")
        monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", "my-secret")
        monkeypatch.setenv("ECOSYSTEM_SERVICE_NAME", "openeye")
        monkeypatch.setenv("ECOSYSTEM_ENABLED", "false")

        config = EcosystemConfig.from_env()
        assert config.registry_url == "http://10.0.0.1:8500"
        assert config.hmac_secret == "my-secret"
        assert config.service_name == "openeye"
        assert config.enabled is False

    def test_static_peers_from_env(self, monkeypatch):
        monkeypatch.setenv(
            "ECOSYSTEM_PEERS",
            "openeye=http://192.168.1.20:8200,ai_for_survival=http://192.168.1.20:8000"
        )
        config = EcosystemConfig.from_env()
        assert config.peers["openeye"] == "http://192.168.1.20:8200"
        assert config.peers["ai_for_survival"] == "http://192.168.1.20:8000"

    def test_static_peers_from_file(self, tmp_path):
        peers_file = tmp_path / "peers.yaml"
        peers_file.write_text(
            "peers:\n"
            "  openeye:\n"
            "    host: '192.168.1.20'\n"
            "    port: 8200\n"
            "    health_endpoint: '/api/ecosystem/health'\n"
            "  magicmirror:\n"
            "    host: '192.168.1.10'\n"
            "    port: 8080\n"
            "    health_endpoint: '/api/v1/health'\n"
        )
        config = EcosystemConfig.from_peers_file(str(peers_file))
        assert "openeye" in config.peers
        assert config.peers["openeye"] == "http://192.168.1.20:8200"
        assert "magicmirror" in config.peers
