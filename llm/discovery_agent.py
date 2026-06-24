"""Discovery agent that queries the registry and builds capability manifests."""

import logging
from typing import Optional

import httpx

from .project_manifest import KNOWN_MANIFESTS, ProjectManifest

logger = logging.getLogger(__name__)


class DiscoveryAgent:
    """
    Discovers ecosystem projects via the registry and builds
    capability manifests suitable for LLM tool-calling.

    Used by AI_For_Survival's RAG pipeline to understand what
    other projects can do and how to interact with them.
    """

    def __init__(self, registry_url: str = "http://localhost:8500",
                 hmac_secret: Optional[str] = None):
        self.registry_url = registry_url
        from ecosystem_auth.tokens import get_ecosystem_secret
        self.hmac_secret = get_ecosystem_secret(hmac_secret)

    def _signed_headers(self, url: str) -> dict:
        """Sign a GET so discovery works when read endpoints require auth."""
        from ecosystem_auth.tokens import sign_request
        return sign_request("GET", url, self.hmac_secret)

    async def discover_all(self) -> list[ProjectManifest]:
        """
        Query the registry for all services and return their capability manifests.

        Merges registry data (live URLs, health) with known static manifests.
        """
        manifests = []
        try:
            url = f"{self.registry_url}/services"
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url, headers=self._signed_headers(url))
                resp.raise_for_status()
                services = resp.json()
        except Exception as e:
            logger.warning(f"Registry unavailable, using static manifests: {e}")
            return list(KNOWN_MANIFESTS.values())

        for service in services:
            name = service.get("name", "")
            manifest = self._build_manifest(name, service)
            if manifest:
                manifests.append(manifest)

        return manifests

    async def discover_one(self, service_name: str) -> Optional[ProjectManifest]:
        """Get a single service's capability manifest."""
        try:
            url = f"{self.registry_url}/services/{service_name}"
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url, headers=self._signed_headers(url))
                resp.raise_for_status()
                service = resp.json()
        except Exception as e:
            logger.warning(f"Could not fetch {service_name} from registry: {e}")
            return KNOWN_MANIFESTS.get(service_name)

        return self._build_manifest(service_name, service)

    def _build_manifest(self, name: str, service_data: dict) -> Optional[ProjectManifest]:
        """Build a manifest from registry data merged with known capabilities."""
        known = KNOWN_MANIFESTS.get(name)
        if known:
            # Update base_url from live registry data
            base_url = service_data.get("base_url", known.base_url)
            return known.model_copy(update={"base_url": base_url})

        # Unknown service — create a minimal manifest
        return ProjectManifest(
            name=name,
            description=service_data.get("metadata", {}).get("description", ""),
            base_url=service_data.get("base_url", ""),
            tags=[],
        )

    def manifests_to_tool_descriptions(self, manifests: list[ProjectManifest]) -> list[dict]:
        """
        Convert manifests into a format suitable for LLM tool-calling.

        Returns a list of tool descriptions that can be fed to an LLM
        as available tools/functions.
        """
        tools = []
        for manifest in manifests:
            for cap in manifest.capabilities:
                for endpoint in cap.endpoints:
                    tools.append({
                        "name": f"{manifest.name.lower()}_{cap.name}_{endpoint.method.lower()}",
                        "description": f"[{manifest.name}] {cap.description}: {endpoint.description}",
                        "method": endpoint.method,
                        "url": f"{manifest.base_url}{endpoint.path}",
                        "parameters": endpoint.parameters,
                        "auth_required": endpoint.auth_required,
                    })
        return tools
