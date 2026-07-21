"""Per-task provider routing — the cost-control lever.

Cloud tokens are metered, so users want them spent selectively: a cloud model for
security analysis (low volume, high value) while chat and embeddings stay local
(high volume, would run up overages). profile.task_providers pins a task to a
provider; a blank/missing entry falls back to the profile-wide preference.
"""
import pytest

from ecosystem_ai.profile import AIProfile, CloudProvider
from ecosystem_ai.providers.base import Capability, ModelInfo
from ecosystem_ai.router import ProviderRouter


class _Prov:
    def __init__(self, name, models=("m1",)):
        self.name = name
        self._models = list(models)

    async def available(self):
        return True

    async def list_models(self):
        return [ModelInfo(name=m, capabilities={Capability.CHAT}) for m in self._models]

    async def pull(self, model, timeout=1800.0):
        self._models.append(model)

    async def chat(self, messages, model=None, tools=None):
        raise AssertionError("not used here")

    def capabilities(self):
        return {Capability.CHAT}


def _profile(**kw):
    p = AIProfile()
    p.cloud["anthropic"] = CloudProvider(enabled=True, model="claude-sonnet-4-5")
    for k, v in kw.items():
        setattr(p, k, v)
    return p


def _router(profile):
    return ProviderRouter(
        profile,
        {"ollama": _Prov("ollama"), "anthropic": _Prov("anthropic")},
        tier=None,
    )


def test_untouched_profile_keeps_the_old_order():
    """A profile with no pins must behave exactly as before: local first."""
    r = _router(_profile())
    assert r._ordered_providers("chat")[0] == "ollama"


def test_pinning_security_to_cloud_leaves_chat_local():
    """The headline case: cloud for security, local for chat."""
    prof = _profile(task_providers={"chat": "ollama", "security": "anthropic"})
    r = _router(prof)
    assert r._ordered_providers("security")[0] == "anthropic"
    assert r._ordered_providers("chat")[0] == "ollama"


def test_pinning_works_in_reverse():
    """...and the inverse, since the user chooses per task."""
    prof = _profile(task_providers={"chat": "anthropic", "security": "ollama"})
    r = _router(prof)
    assert r._ordered_providers("chat")[0] == "anthropic"
    assert r._ordered_providers("security")[0] == "ollama"


def test_blank_pin_falls_back_to_profile_preference():
    prof = _profile(task_providers={"chat": "", "security": ""}, default_provider="ollama")
    r = _router(prof)
    assert r._ordered_providers("chat")[0] == "ollama"


def test_unknown_task_falls_back_to_profile_preference():
    prof = _profile(task_providers={"security": "anthropic"})
    r = _router(prof)
    assert r._ordered_providers("vision")[0] == "ollama"


def test_pinned_provider_is_not_duplicated_in_the_fallback_order():
    prof = _profile(task_providers={"security": "anthropic"})
    order = _router(prof)._ordered_providers("security")
    assert order.count("anthropic") == 1


@pytest.mark.asyncio
async def test_pick_uses_the_pinned_cloud_model_for_that_task():
    prof = _profile(task_providers={"security": "anthropic"})
    prov, model = await _router(prof).pick("security")
    assert prov.name == "anthropic"
    assert model == "claude-sonnet-4-5"


@pytest.mark.asyncio
async def test_pinning_local_while_default_is_cloud_still_checks_installed_models():
    """Regression: classifying by 'differs from default_provider' broke this.

    With default_provider=anthropic and chat pinned to ollama, the local branch
    must still run, so an uninstalled recommendation falls back to what is
    actually installed instead of 404ing.
    """
    prof = _profile(default_provider="anthropic", task_providers={"chat": "ollama"})
    prof.selected_model = "m1"  # installed on the fake local provider
    prov, model = await _router(prof).pick("chat")
    assert prov.name == "ollama"
    assert model == "m1", "local branch must resolve to an installed model"
