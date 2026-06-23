"""Routes LLM commands/intents to project API calls."""

import logging
import os
import time
from typing import Any, Optional
from urllib.parse import quote

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

    @staticmethod
    def _default_harness_url() -> str:
        """Resolve the harness daemon URL from the environment (evaluated per
        instance, not at import time). ECOSYSTEM_HARNESS_URL wins; otherwise it
        is built from AEGISSIEM_PORT."""
        explicit = os.environ.get("ECOSYSTEM_HARNESS_URL")
        if explicit:
            return explicit.rstrip("/")
        return f"http://localhost:{os.environ.get('AEGISSIEM_PORT', '8088')}"

    def __init__(
        self,
        discovery: Optional[DiscoveryAgent] = None,
        hmac_secret: Optional[str] = None,
        harness_url: Optional[str] = None,
    ):
        from auth.python.ecosystem_auth.tokens import get_ecosystem_secret

        self.discovery = discovery or DiscoveryAgent()
        self.hmac_secret = get_ecosystem_secret(hmac_secret)
        self._harness_base_url = harness_url or self._default_harness_url()
        self._manifests: dict[str, ProjectManifest] = {}
        self._harness_ok: bool | None = None
        self._harness_checked_at: float = 0
        self._harness_cache_ttl: float = 30.0
        # Single shared, persistent connection pool. Per-request timeouts are
        # passed at call sites so one client covers fast probes and slow analyses.
        self._client = httpx.AsyncClient(timeout=10.0)

    async def aclose(self) -> None:
        """Close the shared HTTP connection pool."""
        await self._client.aclose()

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
                # URL-encode substituted values so untrusted (LLM-supplied)
                # params cannot inject path traversal or extra path segments.
                url = url.replace(f"{{{key}}}", quote(str(value), safe=""))

        headers = {}
        if endpoint.auth_required:
            from auth.python.ecosystem_auth.tokens import sign_request

            sign_body = None if endpoint.method.upper() in ("GET", "DELETE") else body
            headers.update(
                sign_request(endpoint.method, url, self.hmac_secret, sign_body)
            )

        try:
            if endpoint.method.upper() in ("POST", "PUT", "PATCH"):
                resp = await self._client.request(
                    endpoint.method, url, json=body, headers=headers
                )
            else:
                resp = await self._client.request(endpoint.method, url, headers=headers)

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
            resp = await self._client.get(
                f"{self._harness_base_url}/api/status", timeout=2.0
            )
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
            resp = await self._client.post(
                f"{self._harness_base_url}/api/analyze",
                json={"project": project, "capability": capability, **body},
                timeout=30.0,
            )
            if resp.status_code == 200:
                return {"status": "ok", "data": resp.json(), "source": "harness"}
        except Exception as e:
            logger.debug("Harness request failed: %s", e)
        return {"status": "error", "detail": "harness unavailable"}
