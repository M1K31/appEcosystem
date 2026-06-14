"""Routes LLM commands/intents to project API calls."""

import logging
import os
import time
from typing import Any, Optional

import httpx

from .discovery_agent import DiscoveryAgent
from .project_manifest import ProjectManifest

logger = logging.getLogger(__name__)


class CommandRouter:
    """
    Translates high-level LLM intents into concrete API calls
    against ecosystem services.

    The LLM produces intents like:
        {"action": "check_cameras", "project": "openeye"}

    The router resolves this to the correct HTTP call using
    the project's capability manifest.
    """

    _HARNESS_CAPABILITIES = frozenset({
        "threat_analysis", "log_analysis", "security_scan",
        "incident_triage", "block_ip", "security_status",
    })
    _HARNESS_BASE_URL = f"http://localhost:{os.environ.get('ASUSGUARD_PORT', '8088')}"

    def __init__(
        self,
        discovery: Optional[DiscoveryAgent] = None,
        hmac_secret: Optional[str] = None,
    ):
        from auth.python.ecosystem_auth.tokens import get_ecosystem_secret

        self.discovery = discovery or DiscoveryAgent()
        self.hmac_secret = get_ecosystem_secret(hmac_secret)
        self._manifests: dict[str, ProjectManifest] = {}
        self._harness_ok: bool | None = None
        self._harness_checked_at: float = 0
        self._harness_cache_ttl: float = 30.0

    async def refresh_manifests(self) -> None:
        """Refresh the cached capability manifests from the registry."""
        manifests = await self.discovery.discover_all()
        self._manifests = {m.name.lower(): m for m in manifests}
        logger.info(f"Refreshed {len(self._manifests)} project manifests")

    async def route(
        self,
        project: str,
        capability: str,
        method: str = "GET",
        path_params: Optional[dict] = None,
        body: Optional[dict] = None,
    ) -> dict[str, Any]:
        """
        Route a command to the appropriate project API.

        Args:
            project: Project name (e.g., 'openeye')
            capability: Capability name (e.g., 'camera_monitoring')
            method: HTTP method
            path_params: URL path parameters to substitute
            body: Request body for POST/PUT

        Returns:
            Dict with status, data, and any error info.
        """
        # Try cyber-claude-harness for security capabilities
        if capability in self._HARNESS_CAPABILITIES and await self._harness_available():
            result = await self._route_via_harness(project, capability, body or {})
            if result.get("status") == "ok":
                return result
            logger.debug("Harness routing failed for %s/%s, falling back to direct API", project, capability)

        if not self._manifests:
            await self.refresh_manifests()

        manifest = self._manifests.get(project.lower())
        if not manifest:
            return {"status": "error", "detail": f"Unknown project: {project}"}

        # Find matching capability and endpoint
        for cap in manifest.capabilities:
            if cap.name == capability:
                for endpoint in cap.endpoints:
                    if endpoint.method.upper() == method.upper():
                        return await self._execute(
                            manifest.base_url, endpoint, path_params, body
                        )

        return {"status": "error", "detail": f"No matching endpoint for {capability}/{method}"}

    async def _execute(
        self,
        base_url: str,
        endpoint,
        path_params: Optional[dict],
        body: Optional[dict],
    ) -> dict[str, Any]:
        """Execute an HTTP call to a project endpoint."""
        url = f"{base_url}{endpoint.path}"
        if path_params:
            for key, value in path_params.items():
                url = url.replace(f"{{{key}}}", str(value))

        headers = {}
        if endpoint.auth_required:
            from auth.python.ecosystem_auth.tokens import sign_payload

            if endpoint.method.upper() in ("GET", "DELETE"):
                payload_to_sign = {"url": url, "method": endpoint.method.upper()}
            else:
                payload_to_sign = body if body is not None else {}
            headers["X-Ecosystem-Signature"] = sign_payload(payload_to_sign, self.hmac_secret)

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                if endpoint.method.upper() in ("POST", "PUT", "PATCH"):
                    resp = await client.request(
                        endpoint.method, url, json=body, headers=headers
                    )
                else:
                    resp = await client.request(endpoint.method, url, headers=headers)

            return {
                "status": "ok" if resp.status_code < 400 else "error",
                "http_status": resp.status_code,
                "data": resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text,
            }
        except Exception as e:
            return {"status": "error", "detail": str(e)}

    async def _harness_available(self) -> bool:
        """Check if the cyber-claude-harness daemon is reachable (cached)."""
        now = time.monotonic()
        if self._harness_ok is not None and (now - self._harness_checked_at) < self._harness_cache_ttl:
            return self._harness_ok
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(f"{self._HARNESS_BASE_URL}/api/status")
                self._harness_ok = resp.status_code == 200
        except Exception:
            self._harness_ok = False
        self._harness_checked_at = now
        return self._harness_ok

    async def _route_via_harness(
        self, project: str, capability: str, body: dict
    ) -> dict[str, Any]:
        """Route a security capability through the harness daemon."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    f"{self._HARNESS_BASE_URL}/api/analyze",
                    json={"project": project, "capability": capability, **body},
                )
                if resp.status_code == 200:
                    return {"status": "ok", "data": resp.json(), "source": "harness"}
        except Exception as e:
            logger.debug("Harness request failed: %s", e)
        return {"status": "error", "detail": "harness unavailable"}
