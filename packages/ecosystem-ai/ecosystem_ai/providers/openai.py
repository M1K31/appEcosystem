"""OpenAI provider — opt-in cloud backend.

Uses the Chat Completions API. `base_url` is configurable so any
OpenAI-compatible gateway (self-hosted proxies, Copilot-style endpoints) can be
targeted with the same provider.
"""

from __future__ import annotations

import os
from typing import Optional

import httpx

from .base import Capability, ChatMessage, ChatResult, ModelInfo, ProviderError

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o"
DEFAULT_EMBED_MODEL = "text-embedding-3-small"


class OpenAIProvider:
    name = "openai"

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = DEFAULT_BASE_URL,
        *,
        default_model: str = DEFAULT_MODEL,
        client: Optional[httpx.AsyncClient] = None,
        timeout: float = 60.0,
    ):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    def capabilities(self) -> set[Capability]:
        return {Capability.CHAT, Capability.TOOLS, Capability.VISION,
                Capability.EMBED, Capability.STREAM}

    async def available(self) -> bool:
        return bool(self.api_key)

    async def list_models(self) -> list[ModelInfo]:
        return [ModelInfo(name=self.default_model, family="gpt",
                          capabilities={Capability.CHAT})]

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}", "content-type": "application/json"}

    async def chat(
        self,
        messages: list[ChatMessage],
        model: Optional[str] = None,
        *,
        tools: Optional[list[dict]] = None,
        stream: bool = False,
    ) -> ChatResult:
        if not self.api_key:
            raise ProviderError("openai: OPENAI_API_KEY not set")
        mdl = model or self.default_model
        payload: dict = {
            "model": mdl,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
        }
        if tools:
            payload["tools"] = tools
        try:
            resp = await self._client.post(
                f"{self.base_url}/chat/completions", json=payload, headers=self._headers()
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            raise ProviderError(f"openai chat failed: {e}") from e
        choices = data.get("choices", []) or []
        text = choices[0].get("message", {}).get("content", "") if choices else ""
        return ChatResult(text=text, model=mdl, provider=self.name,
                          usage=data.get("usage", {}) or {}, raw=data)

    async def embed(self, text: str, model: Optional[str] = None) -> list[float]:
        if not self.api_key:
            raise ProviderError("openai: OPENAI_API_KEY not set")
        mdl = model or DEFAULT_EMBED_MODEL
        try:
            resp = await self._client.post(
                f"{self.base_url}/embeddings",
                json={"model": mdl, "input": text}, headers=self._headers(),
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            raise ProviderError(f"openai embed failed: {e}") from e
        return (data.get("data", [{}])[0] or {}).get("embedding", [])
