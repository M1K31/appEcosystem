"""WP8 hardening & operability tests for appEcosystem."""
from __future__ import annotations

from pathlib import Path

from cli.commands import cmd_totp_recover
from ecosystem_policy.approval_queue import LocalApprovalQueue
from ecosystem_policy.step_up import StepUpAuthenticator, compute_totp


def test_local_approval_queue_list_approvals_without_status(tmp_path: Path):
    """Regression test: list_approvals(status=None) must pass a 1-tuple to sqlite3."""
    queue = LocalApprovalQueue(db_path=tmp_path / "approvals.db")
    queue.request_approval(
        requester_service="ai_for_survival",
        actor="blue-team",
        action="containment.block_ip",
        action_class="contain",
        target={"scope": "lan", "identifier": "192.168.1.50"},
        summary="Repeated failed logins",
        ttl_seconds=600,
    )
    queue.request_approval(
        requester_service="aegissiem",
        actor="triage",
        action="containment.quarantine_device",
        action_class="remediate",
        target={"scope": "lan", "identifier": "192.168.1.51"},
        summary="Lateral movement",
        ttl_seconds=600,
    )

    all_rows = queue.list_approvals(limit=10)
    assert len(all_rows) == 2

    pending_rows = queue.list_approvals(status="pending", limit=10)
    assert len(pending_rows) == 2

    limited_rows = queue.list_approvals(limit=1)
    assert len(limited_rows) == 1


def test_step_up_reset_totp_clears_secret_lockout_and_preserves_other_factors(tmp_path: Path):
    """reset_totp removes TOTP secret and lockout state without touching other factors."""
    store = tmp_path / "step_up_credentials.json"
    auth = StepUpAuthenticator(
        store_path=store,
        signing_secret="wp8-test-secret",
        max_totp_failures=2,
        totp_lockout_seconds=900,
    )

    enrolled = auth.enroll_totp("admin")
    assert auth.has_enrolled_factors("admin")["totp"] is True

    # Trigger lockout via bad codes
    assert auth.verify_totp_and_issue_token("admin", "000000", now=1000.0) is None
    assert auth.verify_totp_and_issue_token("admin", "000000", now=1001.0) is None
    valid_code = compute_totp(enrolled["secret"], timestamp=1002.0)
    assert auth.verify_totp_and_issue_token("admin", valid_code, now=1002.0) is None  # locked out

    # Local recovery removes TOTP and clears lockout
    assert auth.reset_totp("admin") is True
    assert auth.reset_totp("admin") is False  # idempotent
    assert auth.has_enrolled_factors("admin")["totp"] is False
    assert auth.has_any_enrolled_operator() is False

    # Re-enrollment works immediately without leftover lockout
    re_enrolled = auth.enroll_totp("admin")
    new_code = compute_totp(re_enrolled["secret"], timestamp=1035.0)
    token = auth.verify_totp_and_issue_token("admin", new_code, now=1035.0)
    assert token is not None
    assert token["operator_id"] == "admin"


def test_cmd_totp_recover_cli(tmp_path: Path, capsys):
    """CLI totp-recover lists operators, refuses without --yes, and resets with --yes."""
    store = tmp_path / "step_up_credentials.json"
    auth = StepUpAuthenticator(store_path=store, signing_secret="wp8-test-secret")
    auth.enroll_totp("owner")

    # List mode
    assert cmd_totp_recover(list_only=True, store_path=str(store)) == 0
    out = capsys.readouterr().out
    assert "owner" in out
    assert "yes" in out

    # Refuse without --yes
    assert cmd_totp_recover("owner", confirm=False, store_path=str(store)) == 2
    assert auth.has_enrolled_factors("owner")["totp"] is True

    # Reset with --yes
    assert cmd_totp_recover("owner", confirm=True, store_path=str(store)) == 0
    assert auth.has_enrolled_factors("owner")["totp"] is False

    # Missing operator returns 1
    assert cmd_totp_recover("owner", confirm=True, store_path=str(store)) == 1
