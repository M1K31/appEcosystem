"""Google Gemini provider — opt-in cloud backend (generateContent API)."""

from __future__ import annotations

import os
from typing import Optional

import httpx

from .base import Capability, ChatMessage, ChatResult, ModelInfo, ProviderError

DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_MODEL = "gemini-1.5-flash"


class GeminiProvider:
    name = "gemini"

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = DEFAULT_BASE_URL,
        *,
        default_model: str = DEFAULT_MODEL,
        client: Optional[httpx.AsyncClient] = None,
        timeout: float = 60.0,
    ):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY", "")
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    def capabilities(self) -> set[Capability]:
        return {Capability.CHAT, Capability.VISION, Capability.EMBED, Capability.STREAM}

    async def available(self) -> bool:
        return bool(self.api_key)

    async def list_models(self) -> list[ModelInfo]:
        return [ModelInfo(name=self.default_model, family="gemini",
                          capabilities={Capability.CHAT})]

    async def chat(
        self,
        messages: list[ChatMessage],
        model: Optional[str] = None,
        *,
        tools: Optional[list[dict]] = None,
        stream: bool = False,
    ) -> ChatResult:
        if not self.api_key:
            raise ProviderError("gemini: GEMINI_API_KEY/GOOGLE_API_KEY not set")
        mdl = model or self.default_model
        system = "\n".join(m.content for m in messages if m.role == "system")
        contents = [
            {"role": ("model" if m.role == "assistant" else "user"),
             "parts": [{"text": m.content}]}
            for m in messages if m.role in ("user", "assistant")
        ]
        payload: dict = {"contents": contents}
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}
        url = f"{self.base_url}/models/{mdl}:generateContent?key={self.api_key}"
        try:
            resp = await self._client.post(url, json=payload,
                                           headers={"content-type": "application/json"})
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            raise ProviderError(f"gemini chat failed: {e}") from e
        cands = data.get("candidates", []) or []
        parts = (cands[0].get("content", {}).get("parts", []) if cands else []) or []
        text = "".join(p.get("text", "") for p in parts)
        return ChatResult(text=text, model=mdl, provider=self.name,
                          usage=data.get("usageMetadata", {}) or {}, raw=data)

    async def embed(self, text: str, model: Optional[str] = None) -> list[float]:
        if not self.api_key:
            raise ProviderError("gemini: GEMINI_API_KEY/GOOGLE_API_KEY not set")
        mdl = model or "text-embedding-004"
        url = f"{self.base_url}/models/{mdl}:embedContent?key={self.api_key}"
        try:
            resp = await self._client.post(
                url,
                json={"content": {"parts": [{"text": text}]}},
                headers={"content-type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            raise ProviderError(f"gemini embed failed: {e}") from e
        return (data.get("embedding", {}) or {}).get("values", [])
