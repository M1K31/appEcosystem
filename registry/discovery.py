"""Zeroconf mDNS service announcement and discovery with static config fallback."""

import logging
import socket
from typing import Optional

logger = logging.getLogger(__name__)


class EcosystemDiscovery:
    """
    Announces the ecosystem registry via mDNS and discovers peer services.

    Falls back to static configuration from ecosystem.yaml when mDNS
    is unavailable (e.g., Docker, cloud VMs without multicast).
    """

    SERVICE_TYPE = "_ecosystem._tcp.local."

    def __init__(self, registry_port: int = 8500, host: Optional[str] = None):
        self.registry_port = registry_port
        self.host = host or self._get_local_ip()
        self._zeroconf = None
        self._service_info = None

    async def start(self) -> None:
        """Start mDNS announcement."""
        try:
            from zeroconf import ServiceInfo, Zeroconf

            self._zeroconf = Zeroconf()
            self._service_info = ServiceInfo(
                self.SERVICE_TYPE,
                f"ecosystem-registry.{self.SERVICE_TYPE}",
                addresses=[socket.inet_aton(self.host)],
                port=self.registry_port,
                properties={
                    b"version": b"0.1.0",
                    b"role": b"registry",
                },
            )
            self._zeroconf.register_service(self._service_info)
            logger.info(
                f"mDNS: Announced ecosystem registry at {self.host}:{self.registry_port}"
            )
        except ImportError:
            logger.warning("zeroconf not installed - mDNS disabled, using static config fallback")
        except Exception as e:
            logger.warning(f"mDNS announcement failed: {e} - using static config fallback")

    async def stop(self) -> None:
        """Stop mDNS announcement."""
        if self._zeroconf and self._service_info:
            try:
                self._zeroconf.unregister_service(self._service_info)
                self._zeroconf.close()
                logger.info("mDNS: Unregistered ecosystem registry")
            except Exception as e:
                logger.warning(f"mDNS cleanup error: {e}")

    def discover_services(self) -> list[dict]:
        """
        Discover ecosystem services via mDNS browse.

        Returns a list of dicts with name, host, port for each discovered service.
        """
        discovered = []
        try:
            from zeroconf import ServiceBrowser, Zeroconf

            zc = Zeroconf()
            services_found = []

            class Listener:
                def add_service(self, zc, type_, name):
                    info = zc.get_service_info(type_, name)
                    if info:
                        services_found.append({
                            "name": name.replace(f".{type_}", ""),
                            "host": socket.inet_ntoa(info.addresses[0]) if info.addresses else "unknown",
                            "port": info.port,
                        })

                def remove_service(self, zc, type_, name):
                    pass

                def update_service(self, zc, type_, name):
                    pass

            ServiceBrowser(zc, self.SERVICE_TYPE, Listener())
            import time
            time.sleep(2)  # Allow time for discovery
            zc.close()
            discovered = services_found
        except ImportError:
            logger.debug("zeroconf not available for discovery")
        except Exception as e:
            logger.debug(f"mDNS discovery failed: {e}")

        return discovered

    @staticmethod
    def _get_local_ip() -> str:
        """Get the local machine's primary IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
