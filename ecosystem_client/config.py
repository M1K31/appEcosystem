"""Configuration for the ecosystem client."""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class EcosystemConfig:
    """Ecosystem client configuration loaded from env vars, files, or defaults."""

    registry_url: str = "http://localhost:8500"
    # Fail-closed: no default secret. A committed shared secret is a forgeable
    # credential. Unset => outbound requests are signed with an empty key and
    # rejected by peers (who require a real secret), which is the safe outcome.
    hmac_secret: str = ""
    service_name: str | None = None
    service_port: int | None = None
    health_endpoint: str = "/health"
    webhook_path: str = "/ecosystem/events"
    enabled: bool = True
    discovery_interval: int = 60
    request_timeout: float = 5.0
    event_retry_attempts: int = 3
    event_retry_delay: float = 5.0
    priority: int = 0
    peers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> "EcosystemConfig":
        """Load config from environment variables."""
        peers = {}
        peers_str = os.environ.get("ECOSYSTEM_PEERS", "")
        if peers_str:
            for pair in peers_str.split(","):
                pair = pair.strip()
                if "=" in pair:
                    name, url = pair.split("=", 1)
                    peers[name.strip()] = url.strip()

        enabled_str = os.environ.get("ECOSYSTEM_ENABLED", "true")
        enabled = enabled_str.lower() not in ("false", "0", "no")

        port_str = os.environ.get("ECOSYSTEM_SERVICE_PORT")
        port = int(port_str) if port_str else None

        hmac_secret = os.environ.get("ECOSYSTEM_HMAC_SECRET", cls.hmac_secret)
        if not hmac_secret:
            logger.warning(
                "ECOSYSTEM_HMAC_SECRET is not set — outbound ecosystem requests "
                "will be unsigned/unverifiable by peers. Set it to enable "
                "inter-service auth."
            )

        return cls(
            registry_url=os.environ.get("ECOSYSTEM_REGISTRY_URL", cls.registry_url),
            hmac_secret=hmac_secret,
            service_name=os.environ.get("ECOSYSTEM_SERVICE_NAME"),
            service_port=port,
            health_endpoint=os.environ.get(
                "ECOSYSTEM_HEALTH_ENDPOINT", cls.health_endpoint
            ),
            enabled=enabled,
            discovery_interval=int(
                os.environ.get("ECOSYSTEM_DISCOVERY_INTERVAL", cls.discovery_interval)
            ),
            priority=int(os.environ.get("ECOSYSTEM_PRIORITY", "0")),
            peers=peers,
        )

    @classmethod
    def from_peers_file(cls, path: str) -> "EcosystemConfig":
        """Load static peers from a YAML file."""
        import yaml

        config = cls()
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            for name, info in (data.get("peers") or {}).items():
                host = info.get("host", "localhost")
                port = info.get("port", 8000)
                config.peers[name] = f"http://{host}:{port}"
        except Exception:
            pass
        return config
