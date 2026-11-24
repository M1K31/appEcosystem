import json
from pathlib import Path

import pytest

from ecosystem_ai.floor_store import (
    clear_recorded_floor_passes,
    get_floor_passes_path,
    load_recorded_floor_passes,
    record_floor_pass,
)


def test_missing_store_returns_empty_set(tmp_path):
    store_file = tmp_path / "nonexistent.json"
    assert load_recorded_floor_passes(store_file) == set()


def test_record_and_load_roundtrip(tmp_path):
    store_file = tmp_path / "floor_passes.json"
    record_floor_pass("model-a:latest", store_file)
    record_floor_pass("model-b:latest", store_file)

    loaded = load_recorded_floor_passes(store_file)
    assert loaded == {"model-a:latest", "model-b:latest"}


def test_corrupt_file_returns_empty_set_safely(tmp_path):
    store_file = tmp_path / "corrupt.json"
    store_file.write_text("invalid-json{{{", encoding="utf-8")
    assert load_recorded_floor_passes(store_file) == set()


def test_clear_recorded_passes(tmp_path):
    store_file = tmp_path / "floor_passes.json"
    record_floor_pass("model-a:latest", store_file)
    assert store_file.exists()
    clear_recorded_floor_passes(store_file)
    assert not store_file.exists()
    assert load_recorded_floor_passes(store_file) == set()


def test_env_override_path(monkeypatch, tmp_path):
    env_file = tmp_path / "env_passes.json"
    monkeypatch.setenv("ECOSYSTEM_FLOOR_PASSES_PATH", str(env_file))
    assert get_floor_passes_path() == env_file
    record_floor_pass("model-from-env", env_file)
    assert "model-from-env" in load_recorded_floor_passes()
