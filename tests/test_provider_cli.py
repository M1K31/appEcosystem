"""`ecosystem provider` never echoes a key."""
import pytest

from cli.commands import cmd_provider
from registry.credential_store import ProviderCredentialStore


@pytest.fixture(autouse=True)
def _keys(tmp_path, monkeypatch):
    monkeypatch.setenv("ECOSYSTEM_PROVIDER_KEYS_FILE", str(tmp_path / "keys.json"))


def test_list_shows_masked_status(capsys):
    ProviderCredentialStore().set_key("anthropic", "sk-test-000000005555")
    assert cmd_provider("list") == 0
    out = capsys.readouterr().out
    assert "anthropic" in out and "5555" in out
    assert "sk-test-000000005555" not in out


def test_set_stores_without_echoing(capsys):
    assert cmd_provider("set", "openai", "sk-test-000000006666") == 0
    assert ProviderCredentialStore().get_key("openai") == "sk-test-000000006666"
    assert "sk-test-000000006666" not in capsys.readouterr().out


def test_delete_removes(capsys):
    ProviderCredentialStore().set_key("gemini", "sk-test-000000000000")
    assert cmd_provider("delete", "gemini") == 0
    assert ProviderCredentialStore().get_key("gemini") is None


def test_unknown_provider_is_an_error():
    assert cmd_provider("set", "hackerllm", "sk-test-000000000000") != 0
