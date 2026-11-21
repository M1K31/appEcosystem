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


# ---- self-registration (approval-gated) and first-party keys -------------------------


def test_register_self_creates_a_pending_inert_key(store):
    rec, secret = store.register_self("org.widget", "Widget", owner="dev@widget",
                                      requested_names=["widget_sensor"], requested_scopes=["commands:dispatch"])
    assert rec["status"] == "pending"
    assert rec["owned_names"] == [] and rec["scopes"] == []          # no grants yet
    assert rec["requested_names"] == ["widget_sensor"]
    assert rec["requested_scopes"] == ["commands:dispatch"]
    assert rec["first_party"] is False
    assert secret
    # A pending key authenticates nothing until approved.
    assert store.get_by_key_id(rec["key_id"]) is None


def test_register_self_will_not_overwrite_an_existing_app(store):
    store.add("org.widget", "Widget", "dev@widget", ["widget_sensor"])
    with pytest.raises(ValueError):
        store.register_self("org.widget", "Widget", requested_names=["widget_sensor"])


def test_register_self_is_capped(store):
    for i in range(store.MAX_PENDING):
        store.register_self(f"org.p{i}", "P", requested_names=[f"p{i}"])
    with pytest.raises(ValueError):
        store.register_self("org.one-too-many", "P", requested_names=["ponemore"])


def test_approve_grants_names_and_scopes_and_activates(store):
    rec, _ = store.register_self("org.widget", "Widget", requested_names=["widget_sensor"],
                                 requested_scopes=["commands:dispatch"])
    approved = store.approve("org.widget", owned_names=["widget_sensor"],
                             scopes=["commands:dispatch", "commands:read"])
    assert approved["status"] == "approved"
    assert approved["owned_names"] == ["widget_sensor"]
    full = store.get_by_key_id(rec["key_id"])                        # now authenticates
    assert full is not None and set(full["scopes"]) == {"commands:dispatch", "commands:read"}


def test_approve_refuses_a_reserved_name_for_a_third_party(store):
    store.register_self("org.evil", "Evil", requested_names=["openeye"])
    with pytest.raises(ValueError):
        store.approve("org.evil", owned_names=["openeye"], scopes=[])


def test_reject_removes_the_pending_record(store):
    rec, _ = store.register_self("org.widget", "Widget", requested_names=["widget_sensor"])
    assert store.reject("org.widget") is True
    assert store.get("org.widget") is None
    assert store.reject("org.widget") is False


def test_first_party_key_may_own_a_reserved_name(store):
    rec, secret = store.add("aegissiem", "AegisSIEM", "owner", ["aegissiem"],
                            scopes=["*"], first_party=True)
    assert rec["first_party"] is True
    assert rec["owned_names"] == ["aegissiem"]
    full = store.get_by_key_id(rec["key_id"])
    assert full["secret"] == secret


def test_add_still_rejects_a_reserved_name_for_a_third_party(store):
    with pytest.raises(ValueError):
        store.add("org.evil", "Evil", "e@x", ["aegissiem"])   # not first_party


def test_pending_lists_separately(store):
    store.register_self("org.a", "A", requested_names=["a_svc"])
    store.add("org.b", "B", "b@x", ["b_svc"])
    pending = [a["app_id"] for a in store.list() if a["status"] == "pending"]
    assert pending == ["org.a"]


# ---- hardening: reserved ids and wildcard names (security review) --------------------


@pytest.mark.parametrize("bad", ["__owner__", "__internal", "_leading", "", "has space",
                                 "bad*glob", "x" * 129])
def test_register_self_rejects_malformed_or_reserved_app_ids(store, bad):
    with pytest.raises(ValueError):
        store.register_self(bad, "X", requested_names=["ok_name"])


def test_add_rejects_the_owner_app_id(store):
    with pytest.raises(ValueError):
        store.add("__owner__", "Spoof", "e@x", ["spoof_name"])


@pytest.mark.parametrize("name", ["*", "a*", "a?b", "a[b]"])
def test_owned_names_cannot_be_a_wildcard(store, name):
    with pytest.raises(ValueError):
        store.add("org.a", "A", "a@x", [name])
    store.register_self("org.b", "B", requested_names=["ok"])
    with pytest.raises(ValueError):
        store.approve("org.b", owned_names=[name], scopes=[])
