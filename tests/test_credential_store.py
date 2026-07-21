"""Provider API-key store: persistence, masking, permissions."""
import json
import os
import stat

import pytest

from registry.credential_store import ProviderCredentialStore, SUPPORTED_PROVIDERS

_IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


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


def test_file_mode_comes_from_creation_not_a_later_chmod(tmp_path, monkeypatch):
    """Guard against the write-then-chmod anti-pattern.

    open(path, "w") at a permissive umask followed by os.chmod() would also
    end up 0600, but the file is briefly world-readable in between. Prove
    the store never calls os.chmod at all by making it raise if it does.
    """
    p = tmp_path / "provider_keys.json"

    def _boom(*args, **kwargs):
        raise AssertionError("os.chmod should never be called - mode must be set at creation")

    monkeypatch.setattr(os, "chmod", _boom)

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


def test_atomic_write_no_leftover_temp_or_lock_cruft(tmp_path):
    p = tmp_path / "provider_keys.json"
    s = ProviderCredentialStore(path=str(p))
    s.set_key("anthropic", "sk-test-000000000000")
    s.set_key("openai", "sk-test-000000004321")

    # Storing a second provider preserves the first.
    assert s.get_key("anthropic") == "sk-test-000000000000"
    assert s.get_key("openai") == "sk-test-000000004321"

    # No stray temp files left beside the store, and the store re-reads clean.
    leftovers = [f for f in tmp_path.iterdir() if f.name != p.name and not f.name.endswith(".lock")]
    assert leftovers == []
    assert ProviderCredentialStore(path=str(p)).status()["anthropic"]["configured"] is True


@pytest.mark.skipif(_IS_ROOT, reason="chmod 000 is not enforced for root")
def test_permission_error_surfaces_instead_of_looking_unconfigured(tmp_path):
    p = tmp_path / "provider_keys.json"
    s = ProviderCredentialStore(path=str(p))
    s.set_key("anthropic", "sk-test-000000000000")

    os.chmod(p, 0o000)
    try:
        with pytest.raises(PermissionError):
            s.status()
        with pytest.raises(PermissionError):
            s.get_key("anthropic")
    finally:
        os.chmod(p, 0o600)


def test_corrupt_json_raises_naming_path_without_key_material(tmp_path):
    p = tmp_path / "provider_keys.json"
    fake_key = "sk-test-000000000000"
    p.write_text('{"anthropic": {"key": "' + fake_key + '", "broken": ')  # truncated/invalid JSON

    s = ProviderCredentialStore(path=str(p))
    with pytest.raises(ValueError) as exc_info:
        s.status()

    message = str(exc_info.value)
    assert str(p) in message
    assert fake_key not in message


def test_delete_key_validates_unknown_provider(store):
    with pytest.raises(ValueError):
        store.delete_key("hackerllm")


def test_delete_key_returns_false_for_known_but_absent_provider(store):
    assert store.delete_key("gemini") is False
