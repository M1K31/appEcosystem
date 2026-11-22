"""Tests for forged-model verification and registration.

Fixture provenance: ``tests/fixtures/forged/`` was generated once by running
Model Forge's own signer (outside this MIT tree). It holds a Model-Forge-signed
``manifest.json``, its ``Modelfile``, a stand-in ``model.gguf`` whose SHA-256
equals ``manifest["sha256"]``, and the signer's raw Ed25519 public key
(``pubkey.b64``). ``model_forge`` is never imported here (AGPL boundary);
``test_valid_manifest_registers_and_records_metadata`` is the byte-exact
cross-check that our payload mirror matches Model Forge's.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from ecosystem_ai.forge_registry import (
    RegisteredModel,
    register_forged_model,
    verify_forge_manifest,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "forged"
PUBKEY = (FIXTURE_DIR / "pubkey.b64").read_text().strip()
VALID_MANIFEST = json.loads((FIXTURE_DIR / "manifest.json").read_text())


class _Spy:
    def __init__(self):
        self.called = False
        self.args = None

    def __call__(self, model_id, modelfile_path):
        self.called = True
        self.args = (model_id, modelfile_path)


def _raise_filenotfound(model_id, modelfile_path):
    raise FileNotFoundError("ollama")


def _dir_with_wrong_gguf(tmp_path):
    for name in ("manifest.json", "Modelfile", "pubkey.b64"):
        shutil.copy(FIXTURE_DIR / name, tmp_path / name)
    (tmp_path / VALID_MANIFEST["gguf_file"]).write_bytes(b"not the signed bytes")
    return tmp_path


def test_valid_manifest_registers_and_records_metadata():
    spy = _Spy()
    rec = register_forged_model(FIXTURE_DIR, public_key_b64=PUBKEY, ollama_create=spy)
    assert isinstance(rec, RegisteredModel)
    assert rec.model_id and rec.tier in (0, 1, 2, 3) and spy.called
    assert spy.args == (VALID_MANIFEST["model_id"], FIXTURE_DIR / "Modelfile")
    assert len(rec.manifest_sha256) == 64


def test_verify_accepts_real_fixture():
    assert verify_forge_manifest(VALID_MANIFEST, public_key_b64=PUBKEY) is None


def test_tampered_signature_refused():
    bad = dict(VALID_MANIFEST, signature="AAAA")
    with pytest.raises(ValueError):
        verify_forge_manifest(bad, public_key_b64=PUBKEY)


def test_tampered_field_refused():
    bad = dict(VALID_MANIFEST, tier=3)
    with pytest.raises(ValueError):
        verify_forge_manifest(bad, public_key_b64=PUBKEY)


def test_missing_public_key_refused():
    for key in ("", None):
        with pytest.raises(ValueError):
            verify_forge_manifest(VALID_MANIFEST, public_key_b64=key)


def test_digest_mismatch_refused(tmp_path):
    spy = _Spy()
    with pytest.raises(ValueError):
        register_forged_model(
            _dir_with_wrong_gguf(tmp_path), public_key_b64=PUBKEY, ollama_create=spy
        )
    assert not spy.called


def test_unsigned_manifest_refused():
    with pytest.raises(ValueError):
        verify_forge_manifest(
            {k: v for k, v in VALID_MANIFEST.items() if k != "signature"} | {"signature": ""},
            public_key_b64=PUBKEY,
        )


def test_missing_manifest_refused(tmp_path):
    spy = _Spy()
    with pytest.raises(ValueError):
        register_forged_model(tmp_path, public_key_b64=PUBKEY, ollama_create=spy)
    assert not spy.called


def test_missing_ollama_is_a_clean_error():
    with pytest.raises(RuntimeError):
        register_forged_model(
            FIXTURE_DIR, public_key_b64=PUBKEY, ollama_create=_raise_filenotfound
        )
