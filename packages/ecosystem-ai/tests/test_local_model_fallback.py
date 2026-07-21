"""Local model selection must never 404 on an uninstalled recommendation.

resolve_model() yields the hardware tier's *recommended* model, which may not be
installed — Ollama then 404s every call. _ensure_local_model applies a
deliberately conservative rule:

  1. recommended model installed        -> use it (working setups unchanged)
  2. something installed                -> stay local, use what's in use; never download
  3. nothing installed (first run)      -> pull the recommendation and use it
"""
import pytest

from ecosystem_ai.profile import AIProfile
from ecosystem_ai.providers.base import Capability, ModelInfo, ProviderError
from ecosystem_ai.router import ProviderRouter


class _NoPullProvider:
    """A local provider that cannot download models (e.g. a non-Ollama backend)."""

    def __init__(self, installed):
        self._installed = list(installed)
        self.pulled = []

    async def available(self):
        return True

    async def list_models(self):
        return [ModelInfo(name=n, capabilities={Capability.CHAT}) for n in self._installed]

    def capabilities(self):
        return {Capability.CHAT}


class _FakeOllama:
    """Stands in for OllamaProvider: lists models and records any pull."""

    def __init__(self, installed):
        self._installed = list(installed)
        self.pulled = []

    async def available(self):
        return True

    async def list_models(self):
        return [ModelInfo(name=n, capabilities={Capability.CHAT}) for n in self._installed]

    async def pull(self, model, timeout=1800.0):
        self.pulled.append(model)
        self._installed.append(model)

    async def chat(self, messages, model=None, tools=None):
        raise AssertionError("chat should not be called in these tests")

    def capabilities(self):
        return {Capability.CHAT}


def _router(profile, provider):
    return ProviderRouter(profile, {"ollama": provider}, tier=None)


@pytest.mark.asyncio
async def test_case1_recommended_model_installed_is_used_unchanged():
    prov = _FakeOllama(["llama3.1:8b", "mistral:latest"])
    r = _router(AIProfile(), prov)
    assert await r._ensure_local_model(prov, "llama3.1:8b") == "llama3.1:8b"
    assert prov.pulled == [], "must not download when the recommendation is present"


@pytest.mark.asyncio
async def test_case2_falls_back_to_the_explicitly_selected_model():
    """The user's chosen model wins over an arbitrary installed one."""
    prof = AIProfile()
    prof.selected_model = "qwen3.5:latest"
    prov = _FakeOllama(["tinyllama:1.1b", "qwen3.5:latest"])
    r = _router(prof, prov)
    assert await r._ensure_local_model(prov, "llama3.1:8b") == "qwen3.5:latest"
    assert prov.pulled == [], "must not download when something is installed"


@pytest.mark.asyncio
async def test_case2_falls_back_to_an_installed_model_when_selection_is_auto():
    prov = _FakeOllama(["tinyllama:1.1b", "mistral:latest"])
    r = _router(AIProfile(), prov)  # selected_model defaults to "auto"
    chosen = await r._ensure_local_model(prov, "llama3.1:8b")
    assert chosen in ("tinyllama:1.1b", "mistral:latest")
    assert prov.pulled == []


@pytest.mark.asyncio
async def test_case2_ignores_a_selected_model_that_is_not_installed():
    prof = AIProfile()
    prof.selected_model = "not-installed:latest"
    prov = _FakeOllama(["mistral:latest"])
    r = _router(prof, prov)
    assert await r._ensure_local_model(prov, "llama3.1:8b") == "mistral:latest"
    assert prov.pulled == []


@pytest.mark.asyncio
async def test_case3_first_run_pulls_the_recommended_model():
    prov = _FakeOllama([])  # nothing installed at all
    r = _router(AIProfile(), prov)
    assert await r._ensure_local_model(prov, "llama3.1:8b") == "llama3.1:8b"
    assert prov.pulled == ["llama3.1:8b"], "first run must download the recommendation"


@pytest.mark.asyncio
async def test_provider_without_pull_support_is_left_alone():
    """An empty model list is not proof of a first run.

    A provider may simply not enumerate, or may not be Ollama. Downloading
    gigabytes on that assumption would be far too aggressive, so we return the
    resolved name untouched and let the provider surface its own error.
    """
    prov = _NoPullProvider([])
    r = _router(AIProfile(), prov)
    assert await r._ensure_local_model(prov, "llama3.1:8b") == "llama3.1:8b"
    assert prov.pulled == []


@pytest.mark.asyncio
async def test_unlistable_provider_is_left_alone():
    """If we cannot enumerate models, don't second-guess the resolved name."""

    class _Blind(_FakeOllama):
        async def list_models(self):
            raise ProviderError("cannot list")

    prov = _Blind(["whatever"])
    r = _router(AIProfile(), prov)
    assert await r._ensure_local_model(prov, "llama3.1:8b") == "llama3.1:8b"
    assert prov.pulled == []
