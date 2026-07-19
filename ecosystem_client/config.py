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
    # Deployment topology (see topology.py). bind_host is where this service's
    # server should listen; advertise_host is what it registers with the registry
    # so peers can reach it. Defaults resolve from ECOSYSTEM_MODE.
    mode: str = "local"
    bind_host: str = "127.0.0.1"
    advertise_host: str = "127.0.0.1"

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

        # Resolve the shared secret the same way the rest of the ecosystem does:
        # ECOSYSTEM_HMAC_SECRET env var first, then the file-backed secret at
        # ~/.config/ecosystem/secret.env. The installers provision the file and
        # deliberately do NOT export the env var (so no per-plist/launchctl setenv
        # is needed), so a client that only checked the env var signed every
        # request with an empty key and got 401'd by the registry.
        hmac_secret = os.environ.get("ECOSYSTEM_HMAC_SECRET", "")
        if not hmac_secret:
            try:
                from ecosystem_auth.tokens import get_ecosystem_secret

                hmac_secret = get_ecosystem_secret()
            except Exception:
                # No env var, no readable file, or the known dev default: fall
                # through to the empty (fail-closed) secret and warn below.
                hmac_secret = cls.hmac_secret
        if not hmac_secret:
            logger.warning(
                "No ecosystem secret found (ECOSYSTEM_HMAC_SECRET unset and no "
                "readable ~/.config/ecosystem/secret.env) — outbound ecosystem "
                "requests will be unsigned and rejected by peers. Run "
                "`ecosystem secret generate` to provision one."
            )

        from .topology import advertise_host, bind_host, get_mode

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
            mode=get_mode(),
            bind_host=bind_host(),
            advertise_host=advertise_host(),
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
