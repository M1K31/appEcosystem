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
