"""Unit tests for the registry AI profile store."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from registry.profile_store import AIProfileStore, default_profile_dict


def test_default_profile_is_ollama_first():
    p = default_profile_dict()
    assert p["default_provider"] == "ollama"
    assert "cloud" in p and "anthropic" in p["cloud"]


def test_update_bumps_version_and_stamps_writer():
    store = AIProfileStore()
    v0 = store.get()["version"]
    p = store.update({"selected_model": "llama3.1:8b"}, updated_by="afs")
    assert p["selected_model"] == "llama3.1:8b"
    assert p["version"] == v0 + 1
    assert p["updated_by"] == "afs"


def test_update_ignores_non_writable():
    store = AIProfileStore()
    p = store.update({"version": 500, "updated_by": "spoof", "prefer": "cloud"},
                     updated_by="afs")
    assert p["prefer"] == "cloud"      # writable
    assert p["version"] == 2           # server-managed, not 500
    assert p["updated_by"] == "afs"    # from arg, not body


def test_persistence_roundtrip(tmp_path):
    path = str(tmp_path / "ai_profile.json")
    s1 = AIProfileStore(persistence_path=path)
    s1.update({"selected_model": "mistral:7b"}, updated_by="loganalysis")

    s2 = AIProfileStore(persistence_path=path)
    assert s2.get()["selected_model"] == "mistral:7b"
    assert s2.get()["version"] == 2


def test_load_merges_new_default_fields(tmp_path):
    # An old persisted profile missing newer fields still loads with defaults.
    path = tmp_path / "ai_profile.json"
    path.write_text('{"selected_model": "x", "version": 7}')
    s = AIProfileStore(persistence_path=str(path))
    prof = s.get()
    assert prof["selected_model"] == "x"
    assert prof["version"] == 7
    assert "cloud" in prof  # default-filled
