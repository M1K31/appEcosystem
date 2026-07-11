import os
import stat
import pytest
from registry.app_store import AppStore, RESERVED_NAMES, default_apps_path


@pytest.fixture
def store(tmp_path):
    return AppStore(persistence_path=str(tmp_path / "apps.json"))


def test_add_returns_secret_once_and_persists(store, tmp_path):
    rec, secret = store.add("org.acme", "Acme", "dev@acme", ["acme_thermostat"])
    assert rec["app_id"] == "org.acme"
    assert rec["status"] == "approved"
    assert "secret" not in rec
    assert secret and len(secret) >= 20
    assert (tmp_path / "apps.json").exists()


def test_get_by_key_id_returns_full_record_with_secret(store):
    rec, secret = store.add("org.acme", "Acme", "dev@acme", ["acme_thermostat"])
    full = store.get_by_key_id(rec["key_id"])
    assert full["secret"] == secret
    assert full["app_id"] == "org.acme"


def test_get_by_key_id_unknown_returns_none(store):
    assert store.get_by_key_id("nope") is None


def test_suspended_app_not_resolvable_by_key_id(store):
    rec, _ = store.add("org.acme", "Acme", "dev@acme", ["acme_thermostat"])
    store.set_status("org.acme", "suspended")
    assert store.get_by_key_id(rec["key_id"]) is None


def test_add_rejects_reserved_name(store):
    with pytest.raises(ValueError):
        store.add("org.evil", "Evil", "e@x", ["openeye"])


def test_add_rejects_duplicate_owned_name(store):
    store.add("org.a", "A", "a@x", ["shared_name"])
    with pytest.raises(ValueError):
        store.add("org.b", "B", "b@x", ["shared_name"])


def test_add_rejects_duplicate_app_id(store):
    store.add("org.a", "A", "a@x", ["name_a"])
    with pytest.raises(ValueError):
        store.add("org.a", "A2", "a@x", ["name_a2"])


def test_file_is_chmod_600(store, tmp_path):
    store.add("org.acme", "Acme", "dev@acme", ["acme_thermostat"])
    mode = stat.S_IMODE(os.stat(tmp_path / "apps.json").st_mode)
    assert mode == 0o600


def test_live_reload_on_external_change(tmp_path):
    path = str(tmp_path / "apps.json")
    a = AppStore(persistence_path=path)
    rec, _ = a.add("org.acme", "Acme", "dev@acme", ["acme_thermostat"])
    b = AppStore(persistence_path=path)
    b.set_status("org.acme", "suspended")
    assert a.get_by_key_id(rec["key_id"]) is None


def test_corrupt_file_yields_empty_store(tmp_path):
    path = tmp_path / "apps.json"
    path.write_text("{ not json")
    a = AppStore(persistence_path=str(path))
    assert a.list() == []


def test_remove(store):
    store.add("org.acme", "Acme", "dev@acme", ["acme_thermostat"])
    assert store.remove("org.acme") is True
    assert store.get("org.acme") is None
    assert store.remove("org.acme") is False


def test_default_path_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("ECOSYSTEM_APPS_FILE", str(tmp_path / "custom.json"))
    assert default_apps_path() == str(tmp_path / "custom.json")
