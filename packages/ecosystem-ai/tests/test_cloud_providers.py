"""Tests for cloud providers (B1) and the provider factory."""

import asyncio

import pytest

from ecosystem_ai import (
    AnthropicProvider,
    ChatMessage,
    GeminiProvider,
    OpenAIProvider,
    build_providers,
    default_profile,
)
from ecosystem_ai.providers.base import ProviderError


class _Resp:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeHTTP:
    def __init__(self, payload):
        self._payload = payload
        self.last_url = None
        self.last_json = None

    async def post(self, url, json=None, headers=None, **kw):
        self.last_url = url
        self.last_json = json
        return _Resp(200, self._payload)


# --------------------------------------------------------------------------- #
class TestAnthropic:
    def test_available_requires_key(self):
        assert asyncio.run(AnthropicProvider(api_key="").available()) is False
        assert asyncio.run(AnthropicProvider(api_key="k").available()) is True

    def test_chat_parses_content_and_extracts_system(self):
        http = _FakeHTTP({"content": [{"type": "text", "text": "hi there"}],
                          "usage": {"output_tokens": 3}})
        prov = AnthropicProvider(api_key="k", client=http)
        res = asyncio.run(prov.chat(
            [ChatMessage("system", "be brief"), ChatMessage("user", "hello")],
            model="claude-x",
        ))
        assert res.text == "hi there"
        assert res.provider == "anthropic"
        assert http.last_json["system"] == "be brief"
        assert http.last_json["messages"] == [{"role": "user", "content": "hello"}]

    def test_chat_without_key_raises(self):
        prov = AnthropicProvider(api_key="")
        with pytest.raises(ProviderError):
            asyncio.run(prov.chat([ChatMessage("user", "x")], model="claude-x"))

    def test_embed_unsupported(self):
        with pytest.raises(ProviderError):
            asyncio.run(AnthropicProvider(api_key="k").embed("x"))


class TestOpenAI:
    def test_chat_parses_choices(self):
        http = _FakeHTTP({"choices": [{"message": {"content": "yo"}}], "usage": {}})
        prov = OpenAIProvider(api_key="k", client=http)
        res = asyncio.run(prov.chat([ChatMessage("user", "hi")], model="gpt-x"))
        assert res.text == "yo"
        assert res.provider == "openai"
        assert "chat/completions" in http.last_url

    def test_custom_base_url(self):
        prov = OpenAIProvider(api_key="k", base_url="http://gateway:9/v1")
        assert prov.base_url == "http://gateway:9/v1"

    def test_embed(self):
        http = _FakeHTTP({"data": [{"embedding": [0.1, 0.2]}]})
        prov = OpenAIProvider(api_key="k", client=http)
        assert asyncio.run(prov.embed("hi")) == [0.1, 0.2]


class TestGemini:
    def test_chat_parses_candidates_and_maps_roles(self):
        http = _FakeHTTP({"candidates": [{"content": {"parts": [{"text": "gem"}]}}],
                          "usageMetadata": {}})
        prov = GeminiProvider(api_key="k", client=http)
        res = asyncio.run(prov.chat(
            [ChatMessage("assistant", "prior"), ChatMessage("user", "now")],
            model="gemini-x",
        ))
        assert res.text == "gem"
        assert res.provider == "gemini"
        roles = [c["role"] for c in http.last_json["contents"]]
        assert roles == ["model", "user"]  # assistant -> model
        assert "gemini-x:generateContent" in http.last_url


class TestFactory:
    def test_only_ollama_by_default(self):
        providers = build_providers(default_profile())
        assert set(providers) == {"ollama"}

    def test_enabled_cloud_added(self):
        p = default_profile()
        p.cloud["anthropic"].enabled = True
        p.cloud["openai"].enabled = True
        providers = build_providers(p)
        assert set(providers) == {"ollama", "anthropic", "openai"}

    def test_cloud_model_passed_through(self):
        p = default_profile()
        p.cloud["anthropic"].enabled = True
        p.cloud["anthropic"].model = "claude-custom"
        providers = build_providers(p)
        assert providers["anthropic"].default_model == "claude-custom"
