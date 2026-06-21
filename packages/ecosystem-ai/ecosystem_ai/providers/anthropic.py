"""Anthropic (Claude) provider — opt-in cloud backend behind the AIProvider API."""

from __future__ import annotations

import os
from typing import Optional

import httpx

from .base import Capability, ChatMessage, ChatResult, ModelInfo, ProviderError

DEFAULT_BASE_URL = "https://api.anthropic.com"
DEFAULT_MODEL = "claude-sonnet-4-6"
API_VERSION = "2023-06-01"


class AnthropicProvider:
    name = "anthropic"

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = DEFAULT_BASE_URL,
        *,
        default_model: str = DEFAULT_MODEL,
        client: Optional[httpx.AsyncClient] = None,
        timeout: float = 60.0,
    ):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    def capabilities(self) -> set[Capability]:
        return {Capability.CHAT, Capability.TOOLS, Capability.VISION, Capability.STREAM}

    async def available(self) -> bool:
        # Cloud reachability isn't probed on every call; presence of a key is the
        # gate. (A live check would cost a request/tokens.)
        return bool(self.api_key)

    async def list_models(self) -> list[ModelInfo]:
        return [ModelInfo(name=self.default_model, family="claude",
                          capabilities={Capability.CHAT})]

    def _headers(self) -> dict:
        return {
            "x-api-key": self.api_key,
            "anthropic-version": API_VERSION,
            "content-type": "application/json",
        }

    async def chat(
        self,
        messages: list[ChatMessage],
        model: Optional[str] = None,
        *,
        tools: Optional[list[dict]] = None,
        stream: bool = False,
    ) -> ChatResult:
        if not self.api_key:
            raise ProviderError("anthropic: ANTHROPIC_API_KEY not set")
        mdl = model or self.default_model
        # Anthropic takes system separately; messages are user/assistant only.
        system = "\n".join(m.content for m in messages if m.role == "system")
        convo = [
            {"role": ("assistant" if m.role == "assistant" else "user"), "content": m.content}
            for m in messages if m.role in ("user", "assistant")
        ]
        payload: dict = {"model": mdl, "max_tokens": 1024, "messages": convo}
        if system:
            payload["system"] = system
        if tools:
            payload["tools"] = tools
        try:
            resp = await self._client.post(
                f"{self.base_url}/v1/messages", json=payload, headers=self._headers()
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            raise ProviderError(f"anthropic chat failed: {e}") from e
        parts = data.get("content", []) or []
        text = "".join(p.get("text", "") for p in parts if p.get("type") == "text")
        return ChatResult(text=text, model=mdl, provider=self.name,
                          usage=data.get("usage", {}) or {}, raw=data)

    async def embed(self, text: str, model: Optional[str] = None) -> list[float]:
        raise ProviderError("anthropic provider does not support embeddings")
