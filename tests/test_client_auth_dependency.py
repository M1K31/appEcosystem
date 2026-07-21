"""ecosystem_client must fail with an actionable message when ecosystem_auth is absent.

discovery.py signs every outbound registry request with ecosystem_auth, but
pyproject only declares httpx (the two ship as local paths, so a hard dependency
would break path installs). A third party installing only ecosystem-client used
to hit a bare ModuleNotFoundError deep inside a request.
"""
import builtins

import pytest

from ecosystem_client import discovery


def test_require_auth_returns_tokens_when_available():
    tokens = discovery._require_auth()
    assert hasattr(tokens, "sign_request")


def test_missing_ecosystem_auth_raises_actionable_error(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("ecosystem_auth"):
            raise ImportError("No module named 'ecosystem_auth'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(ImportError) as exc:
        discovery._require_auth()

    msg = str(exc.value)
    # The message must name the package and tell the reader how to install it.
    assert "ecosystem-auth" in msg
    assert "pip install" in msg


def test_actionable_error_preserves_the_original_cause(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("ecosystem_auth"):
            raise ImportError("No module named 'ecosystem_auth'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(ImportError) as exc:
        discovery._require_auth()
    assert isinstance(exc.value.__cause__, ImportError)
