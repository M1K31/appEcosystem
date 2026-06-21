"""Tests for the ecosystem_ai foundation (B0)."""

import asyncio

import pytest

from ecosystem_ai import (
    AIProfile,
    CapabilityManager,
    CapabilityTier,
    ChatMessage,
    ChatResult,
    FeatureRequirement,
    HardwareInfo,
    OllamaProvider,
    ProviderRouter,
    default_profile,
    recommended_model,
    tier_for,
)
from ecosystem_ai.providers.base import ProviderError


# --------------------------------------------------------------------------- #
# Profile (the shared, syncable source of truth)
# --------------------------------------------------------------------------- #
class TestProfile:
    def test_default_is_ollama(self):
        p = default_profile()
        assert p.default_provider == "ollama"
        assert p.selected_model == "auto"

    def test_roundtrip(self):
        p = default_profile()
        p2 = AIProfile.from_dict(p.to_dict())
        assert p2.to_dict() == p.to_dict()
        assert p2.cloud["anthropic"].enabled is False

    def test_with_change_bumps_version(self):
        p = default_profile()
        p2 = p.with_change(selected_model="llama3.1:8b", updated_by="ai_for_survival")
        assert p2.selected_model == "llama3.1:8b"
        assert p2.version == p.version + 1
        assert p2.updated_by == "ai_for_survival"
        assert p2.updated_at >= p.updated_at

    def test_merge_local_over_shared(self):
        shared = default_profile()
        merged = shared.merge({"ollama_base_url": "http://gpu-box:11434"})
        assert merged.ollama_base_url == "http://gpu-box:11434"
        # unchanged fields preserved
        assert merged.default_provider == "ollama"

    def test_cloud_enable_roundtrip(self):
        p = default_profile()
        p.cloud["anthropic"].enabled = True
        p.cloud["anthropic"].model = "claude-x"
        p2 = AIProfile.from_dict(p.to_dict())
        assert p2.cloud["anthropic"].enabled is True
        assert p2.cloud["anthropic"].model == "claude-x"


# --------------------------------------------------------------------------- #
# Hardware tiers
# --------------------------------------------------------------------------- #
class TestHardwareTiers:
    def _hw(self, ram, gpu=False, vram=0.0):
        return HardwareInfo(ram_gb=ram, cpu_cores=4, arch="x86_64",
                            os_name="Linux", has_gpu=gpu, vram_gb=vram, free_disk_gb=100)

    def test_minimal(self):
        assert tier_for(self._hw(2)) == CapabilityTier.T0_MINIMAL

    def test_modest(self):
        assert tier_for(self._hw(8)) == CapabilityTier.T1_MODEST

    def test_capable(self):
        assert tier_for(self._hw(16)) == CapabilityTier.T2_CAPABLE

    def test_high_end(self):
        assert tier_for(self._hw(32, gpu=True, vram=16)) == CapabilityTier.T3_HIGH_END

    def test_recommended_model_scales(self):
        assert recommended_model(CapabilityTier.T0_MINIMAL) == ""
        assert "3b" in recommended_model(CapabilityTier.T1_MODEST)
        assert recommended_model(CapabilityTier.T2_CAPABLE).startswith("llama3.1")


# --------------------------------------------------------------------------- #
# Feature gating
# --------------------------------------------------------------------------- #
class TestCapabilityManager:
    def _hw(self, ram, gpu=False):
        return HardwareInfo(ram_gb=ram, cpu_cores=4, arch="x86_64",
                            os_name="Linux", has_gpu=gpu, vram_gb=0.0, free_disk_gb=100)

    def test_disabled_on_low_ram(self):
        cm = CapabilityManager(self._hw(2))
        st = cm.evaluate(FeatureRequirement("big-llm", min_ram_gb=16))
        assert not st.enabled and "RAM" in st.reason

    def test_cloud_lifts_low_hardware(self):
        cm = CapabilityManager(self._hw(2), has_cloud_provider=True)
        st = cm.evaluate(FeatureRequirement("chat", min_ram_gb=16, cloud_capable=True))
        assert st.enabled and "cloud" in st.reason

    def test_gpu_requirement(self):
        cm = CapabilityManager(self._hw(32, gpu=False))
        st = cm.evaluate(FeatureRequirement("vision", needs_gpu=True))
        assert not st.enabled and "GPU" in st.reason

    def test_supported(self):
        cm = CapabilityManager(self._hw(32, gpu=True))
        st = cm.evaluate(FeatureRequirement("chat", min_tier=CapabilityTier.T1_MODEST))
        assert st.enabled


# --------------------------------------------------------------------------- #
# Fakes for provider/router tests
# --------------------------------------------------------------------------- #
class FakeProvider:
    def __init__(self, name, available=True):
        self.name = name
        self._available = available
        self.calls = []

    async def available(self):
        return self._available

    async def list_models(self):
        return []

    async def chat(self, messages, model=None, *, tools=None, stream=False):
        self.calls.append(model)
        return ChatResult(text=f"{self.name}:{model}", model=model or "", provider=self.name)

    async def embed(self, text, model=None):
        return [0.0]

    def capabilities(self):
        return set()


class TestRouter:
    def test_resolve_model_precedence(self):
        p = default_profile()
        p.selected_model = "auto"
        r = ProviderRouter(p, {}, tier=CapabilityTier.T2_CAPABLE)
        # auto -> tier default
        assert r.resolve_model("chat") == "llama3.1:8b"
        p.selected_model = "mistral:7b"
        assert r.resolve_model("chat") == "mistral:7b"

    def test_local_first(self):
        p = default_profile()
        providers = {"ollama": FakeProvider("ollama")}
        r = ProviderRouter(p, providers, tier=CapabilityTier.T2_CAPABLE)
        provider, model = asyncio.run(r.pick("chat"))
        assert provider.name == "ollama"
        assert model == "llama3.1:8b"

    def test_cloud_fallback_when_local_down(self):
        p = default_profile()
        p.cloud["anthropic"].enabled = True
        p.cloud["anthropic"].model = "claude-x"
        providers = {
            "ollama": FakeProvider("ollama", available=False),
            "anthropic": FakeProvider("anthropic", available=True),
        }
        r = ProviderRouter(p, providers, tier=CapabilityTier.T2_CAPABLE)
        provider, model = asyncio.run(r.pick("chat"))
        assert provider.name == "anthropic"
        assert model == "claude-x"

    def test_no_fallback_raises(self):
        p = default_profile()
        p.allow_cloud_fallback = False
        p.cloud["anthropic"].enabled = True
        providers = {
            "ollama": FakeProvider("ollama", available=False),
            "anthropic": FakeProvider("anthropic", available=True),
        }
        r = ProviderRouter(p, providers, tier=CapabilityTier.T2_CAPABLE)
        with pytest.raises(ProviderError):
            asyncio.run(r.pick("chat"))

    def test_chat_returns_uniform_result(self):
        p = default_profile()
        r = ProviderRouter(p, {"ollama": FakeProvider("ollama")}, tier=CapabilityTier.T2_CAPABLE)
        res = asyncio.run(r.chat([ChatMessage("user", "hi")]))
        assert isinstance(res, ChatResult)
        assert res.provider == "ollama"


# --------------------------------------------------------------------------- #
# Ollama provider with a mocked HTTP client
# --------------------------------------------------------------------------- #
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
    def __init__(self, tags=None, chat=None, embed=None, fail=False):
        self._tags = tags or {"models": [{"name": "llama3.1:8b", "size": 123,
                                           "details": {"family": "llama"}}]}
        self._chat = chat or {"message": {"content": "hello"}, "eval_count": 5}
        self._embed = embed or {"embedding": [0.1, 0.2]}
        self._fail = fail

    async def get(self, url, **kw):
        if self._fail:
            raise RuntimeError("conn refused")
        return _Resp(200, self._tags)

    async def post(self, url, **kw):
        if "chat" in url:
            return _Resp(200, self._chat)
        return _Resp(200, self._embed)


class TestOllamaProvider:
    def test_available_true(self):
        prov = OllamaProvider(client=_FakeHTTP())
        assert asyncio.run(prov.available()) is True

    def test_available_false_on_error(self):
        prov = OllamaProvider(client=_FakeHTTP(fail=True))
        assert asyncio.run(prov.available()) is False

    def test_list_models(self):
        prov = OllamaProvider(client=_FakeHTTP())
        models = asyncio.run(prov.list_models())
        assert models[0].name == "llama3.1:8b"
        assert models[0].family == "llama"

    def test_chat_uniform_result(self):
        prov = OllamaProvider(client=_FakeHTTP())
        res = asyncio.run(prov.chat([ChatMessage("user", "hi")], model="llama3.1:8b"))
        assert res.text == "hello"
        assert res.provider == "ollama"
        assert res.usage["eval_count"] == 5

    def test_chat_requires_model(self):
        prov = OllamaProvider(client=_FakeHTTP())
        with pytest.raises(ProviderError):
            asyncio.run(prov.chat([ChatMessage("user", "hi")]))

    def test_embed(self):
        prov = OllamaProvider(client=_FakeHTTP())
        vec = asyncio.run(prov.embed("hello"))
        assert vec == [0.1, 0.2]
