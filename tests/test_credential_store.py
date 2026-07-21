"""Provider API-key store: persistence, masking, permissions."""
import json
import os
import stat

import pytest

from registry.credential_store import ProviderCredentialStore, SUPPORTED_PROVIDERS


@pytest.fixture
def store(tmp_path):
    return ProviderCredentialStore(path=str(tmp_path / "provider_keys.json"))


def test_set_and_get_roundtrip(store):
    store.set_key("anthropic", "sk-test-000000000000")
    assert store.get_key("anthropic") == "sk-test-000000000000"


def test_status_never_exposes_the_key(store):
    store.set_key("openai", "sk-test-000000001234")
    st = store.status()
    assert st["openai"]["configured"] is True
    assert st["openai"]["last4"] == "1234"
    assert "sk-test-000000001234" not in json.dumps(st)


def test_status_lists_all_supported_providers(store):
    st = store.status()
    assert set(st) == set(SUPPORTED_PROVIDERS)
    assert all(v["configured"] is False and v["last4"] == "" for v in st.values())


def test_delete_removes_the_key(store):
    store.set_key("gemini", "sk-test-000000000000")
    assert store.delete_key("gemini") is True
    assert store.get_key("gemini") is None
    assert store.delete_key("gemini") is False


def test_file_is_chmod_600(tmp_path):
    p = tmp_path / "provider_keys.json"
    ProviderCredentialStore(path=str(p)).set_key("anthropic", "sk-test-000000000000")
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


def test_rejects_unknown_provider(store):
    with pytest.raises(ValueError):
        store.set_key("hackerllm", "sk-test-000000000000")


def test_rejects_empty_key(store):
    with pytest.raises(ValueError):
        store.set_key("anthropic", "   ")


def test_missing_file_is_not_an_error(store):
    assert store.get_key("anthropic") is None
    assert store.status()["anthropic"]["configured"] is False
