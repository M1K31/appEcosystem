"""Tests for the shared in-app secret-setup helpers (ecosystem_auth.setup)."""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "auth" / "python"))

from ecosystem_auth import setup as eco_setup  # noqa: E402

VALID = "a" * 64  # 64 hex chars, like token_hex(32)
OTHER = "b" * 64


@pytest.fixture(autouse=True)
def _isolated_secret(tmp_path, monkeypatch):
    """Point the secret file at a temp path and clear the env secret."""
    monkeypatch.setenv("ECOSYSTEM_SECRET_FILE", str(tmp_path / "secret.env"))
    monkeypatch.delenv("ECOSYSTEM_HMAC_SECRET", raising=False)
    yield


def test_status_unconfigured():
    s = eco_setup.secret_status()
    assert s["configured"] is False
    assert s["source"] is None
    assert s["masked"] is None
    assert "secret.env" in s["path"]


def test_apply_then_status_configured():
    s = eco_setup.apply_secret(VALID)
    assert s["configured"] is True
    assert s["source"] == "file"
    # status must never leak the raw value
    assert "secret" not in s
    assert s["masked"].startswith("aaaaaa")


def test_apply_rejects_non_hex():
    with pytest.raises(ValueError, match="hexadecimal"):
        eco_setup.apply_secret("not-a-valid-secret!!")


def test_apply_rejects_empty():
    with pytest.raises(ValueError, match="empty"):
        eco_setup.apply_secret("   ")


def test_apply_rejects_dev_default():
    with pytest.raises(ValueError, match="development default"):
        eco_setup.apply_secret("dev-ecosystem-secret-change-in-production")


def test_overwrite_protection_blocks_change():
    eco_setup.apply_secret(VALID)
    with pytest.raises(ValueError, match="already configured"):
        eco_setup.apply_secret(OTHER)  # different value, no overwrite flag


def test_overwrite_allowed_with_flag():
    eco_setup.apply_secret(VALID)
    s = eco_setup.apply_secret(OTHER, allow_overwrite=True)
    assert s["configured"] is True
    assert s["masked"].startswith("bbbbbb")


def test_reapply_same_value_is_idempotent():
    eco_setup.apply_secret(VALID)
    # same value again is allowed without overwrite (no real change)
    s = eco_setup.apply_secret(VALID)
    assert s["configured"] is True


def test_generate_returns_value_once_and_persists():
    s = eco_setup.generate_secret()
    assert s["configured"] is True
    assert len(s["secret"]) == 64  # token_hex(32)
    # the persisted secret is now reflected by status (without the value)
    again = eco_setup.secret_status()
    assert again["configured"] is True
    assert "secret" not in again
