"""The router must warn when a silent fallback lands on a weak model.

The local fallback is silent by design — it keeps the system working when the
recommended model is not installed. But for security analysis, "working" on a 1B
model means confident, wrong findings. A user who picked a model in one app never
sees that a daemon quietly picked something else, so the warning belongs here in
the shared router, not only in one app's settings page.
"""
import logging

import pytest

from ecosystem_ai.profile import AIProfile
from ecosystem_ai.providers.base import Capability, ModelInfo
from ecosystem_ai.router import ProviderRouter


class _Ollama:
    def __init__(self, models):
        # models: list of (name, parameter_size)
        self._models = list(models)

    async def available(self):
        return True

    async def list_models(self):
        return [
            ModelInfo(name=n, parameter_size=p, capabilities={Capability.CHAT})
            for n, p in self._models
        ]

    async def pull(self, model, timeout=1800.0):
        self._models.append((model, "8B"))

    def capabilities(self):
        return {Capability.CHAT}


def _router(prov):
    return ProviderRouter(AIProfile(), {"ollama": prov}, tier=None)


@pytest.mark.asyncio
async def test_weak_fallback_warns_for_security(caplog):
    prov = _Ollama([("tinyllama:1.1b", "1.1B")])
    r = _router(prov)
    with caplog.at_level(logging.WARNING):
        model = await r._ensure_local_model(prov, "llama3.1:8b", task="security")
    assert model == "tinyllama:1.1b"          # still works — this is a warning, not a block
    assert any("too small" in rec.message or "too small" in str(rec.args)
               for rec in caplog.records), "expected a capability warning"
    assert r.last_capability["level"] == "inadequate"


@pytest.mark.asyncio
async def test_adequate_fallback_does_not_warn(caplog):
    prov = _Ollama([("mistral:latest", "7.2B")])
    r = _router(prov)
    with caplog.at_level(logging.WARNING):
        model = await r._ensure_local_model(prov, "llama3.1:8b", task="security")
    assert model == "mistral:latest"
    assert r.last_capability["level"] == "adequate"
    assert r.last_capability["warning"] is None


@pytest.mark.asyncio
async def test_chat_task_is_not_warned_about(caplog):
    """A small model is a legitimate choice for chat — don't nag."""
    prov = _Ollama([("tinyllama:1.1b", "1.1B")])
    r = _router(prov)
    with caplog.at_level(logging.WARNING):
        await r._ensure_local_model(prov, "llama3.1:8b", task="chat")
    assert not any("too small" in rec.message for rec in caplog.records)
    assert r.last_capability is None, "chat must not set a security verdict"


@pytest.mark.asyncio
async def test_capability_failure_never_breaks_routing(monkeypatch):
    """A broken capability check must not take the whole request down."""
    import ecosystem_ai.capability as cap

    def boom(*a, **k):
        raise RuntimeError("assessment exploded")

    monkeypatch.setattr(cap, "assess_for_security", boom)
    prov = _Ollama([("tinyllama:1.1b", "1.1B")])
    model = await _router(prov)._ensure_local_model(prov, "llama3.1:8b", task="security")
    assert model == "tinyllama:1.1b", "routing must survive a capability-check failure"


@pytest.mark.asyncio
async def test_parameter_size_flows_from_the_provider():
    """ModelInfo must carry parameter_size, or the verdict is always 'unknown'."""
    prov = _Ollama([("tinyllama:1.1b", "1.1B")])
    listed = await prov.list_models()
    assert listed[0].parameter_size == "1.1B"
