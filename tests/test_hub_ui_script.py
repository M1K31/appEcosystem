"""The hub Control Plane page must talk to the policy routes in the shapes they accept.

The page's script is inline JavaScript with no JS test runner, so these tests
pin the request shapes at the text level; the behaviour itself is verified in a
browser against a running hub.
"""
import re

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def ui_script(monkeypatch, tmp_path):
    monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", "c" * 64)
    monkeypatch.setenv("ECOSYSTEM_REGISTRY_FILE", str(tmp_path / "registry.json"))
    monkeypatch.setenv("ECOSYSTEM_CAPABILITIES_FILE", str(tmp_path / "caps.json"))
    monkeypatch.setenv("ECOSYSTEM_NOTIFICATIONS_DB", str(tmp_path / "notify.db"))
    monkeypatch.setenv("ECOSYSTEM_AI_PROFILE_FILE", str(tmp_path / "ai_profile.json"))
    monkeypatch.setenv("ECOSYSTEM_POLICY_KEY_DIR", str(tmp_path / "pkeys"))
    monkeypatch.setenv("ECOSYSTEM_POLICY_STATE_FILE", str(tmp_path / "pstate.json"))
    monkeypatch.setenv("ECOSYSTEM_STEP_UP_FILE", str(tmp_path / "step_up.json"))
    monkeypatch.setenv("ECOSYSTEM_APPROVALS_DB", str(tmp_path / "approvals.db"))
    from registry.app import app

    with TestClient(app) as client:
        resp = client.get("/ui")
        assert resp.status_code == 200
        return resp.text


def _handler(script: str, event: str) -> str:
    """Source of the listener registered for ``event`` (up to the next listener)."""
    start = script.index(f'addEventListener("{event}"')
    nxt = script.find("addEventListener(", start + 10)
    return script[start: nxt if nxt != -1 else len(script)]


def test_override_submit_reads_the_fields_the_modal_emits(ui_script):
    handler = _handler(ui_script, "ecosystem-override-submit")
    # <ecosystem-override-modal> emits duration_id and step_up.{method,credential}
    # (validateOverrideForm's payload). The old names never existed, so every
    # override went out with no credential and the default duration.
    for stale in ("d.duration,", "d.untilRevoked", "d.stepUpCredential"):
        assert stale not in handler, stale
    assert "d.duration_id" in handler
    assert re.search(r"d\.step_up", handler)
    assert "totp_code" in handler
    assert 'until_revoked' in handler


@pytest.mark.parametrize("event,success_toast", [
    ("ecosystem-freeze-request", "Ecosystem Freeze engaged"),
    ("ecosystem-restore-restrictions", "Conservative Restrictions: On restored"),
])
def test_success_is_only_reported_after_the_hub_accepted_the_request(ui_script, event, success_toast):
    handler = _handler(ui_script, event)
    assert success_toast in handler
    # The success toast must come after a check of the response, not straight
    # after the fetch: a refused Freeze must never read as "engaged".
    assert re.search(r"\.ok\b", handler), "response status is never checked"
    assert handler.index(".ok") < handler.index(success_toast)
