"""Ollama provider — the ecosystem's default, local-first LLM backend."""

from __future__ import annotations

from typing import Optional

import httpx

from .base import (
    AIProvider,
    Capability,
    ChatMessage,
    ChatResult,
    ModelInfo,
    ProviderError,
)

DEFAULT_BASE_URL = "http://localhost:11434"


class OllamaProvider:
    """Talks to an Ollama server (`/api/tags`, `/api/chat`, `/api/embeddings`)."""

    name = "ollama"

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        client: Optional[httpx.AsyncClient] = None,
        timeout: float = 60.0,
    ):
        self.base_url = base_url.rstrip("/")
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    def capabilities(self) -> set[Capability]:
        # Tool/vision support is model-dependent; advertised broadly here.
        return {Capability.CHAT, Capability.TOOLS, Capability.EMBED, Capability.STREAM}

    async def available(self) -> bool:
        try:
            resp = await self._client.get(f"{self.base_url}/api/tags", timeout=3.0)
            return resp.status_code == 200
        except Exception:
            return False

    async def pull(self, model: str, timeout: float = 1800.0) -> None:
        """Download a model into Ollama.

        Only used on a genuine first run — when no models are installed at all —
        so an existing setup is never surprised by a multi-gigabyte download.
        The generous timeout reflects real model sizes on a slow link.
        """
        if not model:
            raise ProviderError("ollama pull requires a model name")
        try:
            resp = await self._client.post(
                f"{self.base_url}/api/pull",
                json={"model": model, "stream": False},
                timeout=timeout,
            )
            resp.raise_for_status()
        except Exception as e:
            raise ProviderError(f"ollama pull of {model!r} failed: {e}") from e

    async def list_models(self) -> list[ModelInfo]:
        try:
            resp = await self._client.get(f"{self.base_url}/api/tags")
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            raise ProviderError(f"ollama list_models failed: {e}") from e
        models = []
        for m in data.get("models", []):
            models.append(
                ModelInfo(
                    name=m.get("name", ""),
                    family=(m.get("details", {}) or {}).get("family", ""),
                    size_bytes=m.get("size"),
                    capabilities={Capability.CHAT},
                )
            )
        return models

    async def chat(
        self,
        messages: list[ChatMessage],
        model: Optional[str] = None,
        *,
        tools: Optional[list[dict]] = None,
        stream: bool = False,
    ) -> ChatResult:
        if not model:
            raise ProviderError("ollama chat requires a model")
        payload: dict = {
            "model": model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "stream": False,  # non-streaming aggregation; streaming handled separately
        }
        if tools:
            payload["tools"] = tools
        try:
            resp = await self._client.post(f"{self.base_url}/api/chat", json=payload)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            raise ProviderError(f"ollama chat failed: {e}") from e
        msg = data.get("message", {}) or {}
        return ChatResult(
            text=msg.get("content", ""),
            model=model,
            provider=self.name,
            usage={
                "prompt_eval_count": data.get("prompt_eval_count"),
                "eval_count": data.get("eval_count"),
            },
            raw=data,
        )

    async def embed(self, text: str, model: Optional[str] = None) -> list[float]:
        mdl = model or "nomic-embed-text"
        try:
            resp = await self._client.post(
                f"{self.base_url}/api/embeddings", json={"model": mdl, "prompt": text}
            )
            resp.raise_for_status()
            return resp.json().get("embedding", [])
        except Exception as e:
            raise ProviderError(f"ollama embed failed: {e}") from e
