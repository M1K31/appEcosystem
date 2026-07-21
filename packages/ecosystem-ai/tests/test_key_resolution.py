"""Cloud provider keys resolve from the credential store, then env."""
import pytest

from ecosystem_ai.factory import build_providers, resolve_provider_key
from ecosystem_ai.profile import AIProfile, CloudProvider


def test_store_key_is_used(monkeypatch, tmp_path):
    monkeypatch.setenv("ECOSYSTEM_PROVIDER_KEYS_FILE", str(tmp_path / "keys.json"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from registry.credential_store import ProviderCredentialStore

    ProviderCredentialStore(path=str(tmp_path / "keys.json")).set_key(
        "anthropic", "sk-test-000000001111"
    )
    assert resolve_provider_key("anthropic") == "sk-test-000000001111"


def test_env_var_is_the_fallback(monkeypatch, tmp_path):
    monkeypatch.setenv("ECOSYSTEM_PROVIDER_KEYS_FILE", str(tmp_path / "absent.json"))
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-000000002222")
    assert resolve_provider_key("openai") == "sk-test-000000002222"


def test_enabled_cloud_provider_receives_the_stored_key(monkeypatch, tmp_path):
    monkeypatch.setenv("ECOSYSTEM_PROVIDER_KEYS_FILE", str(tmp_path / "keys.json"))
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    from registry.credential_store import ProviderCredentialStore

    ProviderCredentialStore(path=str(tmp_path / "keys.json")).set_key(
        "openai", "sk-test-000000003333"
    )
    profile = AIProfile()
    profile.cloud["openai"] = CloudProvider(enabled=True, model="gpt-4o-mini")
    providers = build_providers(profile)
    assert providers["openai"].api_key == "sk-test-000000003333"


def test_no_key_anywhere_returns_none(monkeypatch, tmp_path):
    monkeypatch.setenv("ECOSYSTEM_PROVIDER_KEYS_FILE", str(tmp_path / "absent.json"))
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    assert resolve_provider_key("gemini") is None


# --- build_router tier auto-detection -------------------------------------
# A stock profile uses selected_model="auto" and task_models={"chat":"auto"}.
# ProviderRouter.resolve_model() falls back to the tier's recommended model for
# "auto", and with tier=None that fallback returns "" — so build_router(profile)
# used to hand providers an empty model name and every call died with
# "ollama chat requires a model". These pin the fix.

def test_build_router_detects_a_tier_so_auto_resolves():
    from ecosystem_ai.factory import build_router
    from ecosystem_ai.profile import AIProfile

    router = build_router(AIProfile())
    assert router.tier is not None, "build_router must detect a tier when none is given"
    model = router.resolve_model("chat")
    assert model, "a stock 'auto' profile must resolve to a real model name"


def test_explicitly_passed_tier_still_wins():
    from ecosystem_ai.factory import build_router
    from ecosystem_ai.hardware import CapabilityTier
    from ecosystem_ai.profile import AIProfile

    for tier in CapabilityTier:
        router = build_router(AIProfile(), tier=tier)
        assert router.tier == tier
        break
