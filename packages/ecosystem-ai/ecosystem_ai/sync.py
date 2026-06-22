"""Client-side access to the shared ecosystem AI profile.

Apps use `AIProfileClient` to read the shared profile from the registry, write
changes back (so a selection made here appears in every other app), and fall
back to a local profile when the registry is absent (standalone). Request
signing is injected via a `signer` callable so this module stays decoupled from
any specific auth library.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

import httpx

from .profile import AIProfile, default_profile

# signer(method, url, body) -> dict of headers (e.g. ecosystem_auth.sign_request)
Signer = Callable[[str, str, Optional[dict]], dict]


class AIProfileClient:
    def __init__(
        self,
        registry_url: str,
        *,
        service_name: str = "",
        signer: Optional[Signer] = None,
        local_profile: Optional[AIProfile] = None,
        client: Optional[httpx.AsyncClient] = None,
        timeout: float = 5.0,
    ):
        self.registry_url = registry_url.rstrip("/")
        self.service_name = service_name
        self._signer = signer
        self._local = local_profile or default_profile()
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    @property
    def local_profile(self) -> AIProfile:
        return self._local

    def _headers(self, method: str, url: str, body: Optional[dict]) -> dict:
        return self._signer(method, url, body) if self._signer else {}

    async def fetch(self) -> AIProfile:
        """Read the shared profile; fall back to the local one if unreachable."""
        url = f"{self.registry_url}/ai-profile"
        try:
            resp = await self._client.get(url, headers=self._headers("GET", url, None))
            resp.raise_for_status()
            return AIProfile.from_dict(resp.json())
        except Exception:
            return self._local

    async def update(self, changes: dict[str, Any]) -> AIProfile:
        """Write changes to the shared profile (propagates to all apps).

        If the registry is unreachable, the change is applied to the local
        profile so standalone operation still reflects the user's choice.
        """
        url = f"{self.registry_url}/ai-profile"
        try:
            resp = await self._client.put(
                url, json=changes, headers=self._headers("PUT", url, changes)
            )
            resp.raise_for_status()
            return AIProfile.from_dict(resp.json())
        except Exception:
            self._local = self._local.with_change(
                updated_by=self.service_name,
                **{k: v for k, v in changes.items()},
            )
            return self._local

    async def resolve(self, local_overrides: Optional[dict] = None) -> AIProfile:
        """Fetch the shared profile and layer any local overrides on top."""
        prof = await self.fetch()
        return prof.merge(local_overrides) if local_overrides else prof

    def on_profile_changed(self, event_data: dict) -> AIProfile:
        """Update the cached local view from an ecosystem.ai_profile_changed
        event payload (so apps reflect changes live)."""
        prof = event_data.get("profile")
        if isinstance(prof, dict):
            self._local = AIProfile.from_dict(prof)
        return self._local
