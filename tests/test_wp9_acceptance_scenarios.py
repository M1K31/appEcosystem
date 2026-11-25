"""WP9 Acceptance Suite — End-to-end verification of roadmap scenarios S1 through S10.

Exercises the real appEcosystem control plane (PolicyEngine, LocalApprovalQueue,
StepUpAuthenticator, run_action_loop, NotificationRouter, CapabilityRegistry,
ScanRunner, build_scan_request_handler, and resolve_analyst_model)
deterministically with zero live network calls.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from agents.scan_agent.command_handler import (
    SCAN_REQUEST_CAPABILITY,
    build_scan_request_handler,
)
from agents.scan_agent.runner import ScanRequest, ScanRunner
from ecosystem_ai.analyst_select import TIER_ANALYST_MODELS, resolve_analyst_model
from ecosystem_ai.hardware import HardwareInfo
from ecosystem_ai.profile import AIProfile
from ecosystem_client.contracts import build_notification_envelope
from ecosystem_hub.action_loop import run_action_loop
from ecosystem_hub.capabilities import CapabilityRegistry
from ecosystem_policy.approval_queue import LocalApprovalQueue
from ecosystem_policy.engine import ActionRequest, PolicyEngine
from ecosystem_policy.step_up import StepUpAuthenticator, compute_totp
from registry.notifications import NotificationRouter


def _scripted_analyst(rounds_proposals: list[list[dict[str, Any]]]):
    """Build an async analyst callable returning scripted action-proposal.v1 JSON."""
    idx = 0

    async def _analyst(req: str, ctx: dict[str, Any]) -> str:
        nonlocal idx
        if idx < len(rounds_proposals):
            proposals = rounds_proposals[idx]
        else:
            proposals = []
        idx += 1
        return json.dumps({"proposals": proposals})

    return _analyst


class _RecordingHub:
    """In-process hub stub recording dispatched commands and optional side effects."""

    def __init__(self, *, on_invoke=None):
        self.dispatched: list[dict[str, Any]] = []
        self._on_invoke = on_invoke

    async def invoke(
        self,
        capability: str,
        target: Any,
        parameters: dict[str, Any] | None = None,
        rationale: str | None = None,
        idempotency_key: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        entry = {
            "capability": capability,
            "target": target,
            "parameters": dict(parameters or {}),
            "rationale": rationale,
            "idempotency_key": idempotency_key,
        }
        self.dispatched.append(entry)
        if self._on_invoke is not None:
            return await self._on_invoke(entry)
        return {"status": "completed", "command_id": "01WP9TEST00000000000000001", "result": {"confirmed": True}}


def _make_policy_stack(
    tmp_path: Path,
) -> tuple[PolicyEngine, LocalApprovalQueue, StepUpAuthenticator]:
    policy = PolicyEngine(persistence_path=tmp_path / "policy.json")
    step_up = StepUpAuthenticator(
        store_path=tmp_path / "step_up.json",
        signing_secret="wp9-acceptance-secret",
    )
    approvals = LocalApprovalQueue(db_path=tmp_path / "approvals.db", step_up=step_up)
    return policy, approvals, step_up


# ── S1: Blue Team mitigates repeated failed logins from a LAN address ──────

def test_s1_blue_team_mitigates_lan_brute_force(tmp_path: Path):
    policy, approvals, _ = _make_policy_stack(tmp_path)
    notifications = NotificationRouter(persistence_path=tmp_path / "notifications.db")

    analyst = _scripted_analyst(
        [
            [
                {
                    "action": "threat_intel.lookup_ioc",
                    "action_class": "observe",
                    "target": "192.168.1.77",
                    "parameters": {"type": "ip"},
                    "rationale": "Enrich internal brute-force source",
                    "confidence": 0.95,
                },
                {
                    "action": "containment.block_ip",
                    "action_class": "contain",
                    "target": "192.168.1.77",
                    "parameters": {"ttl_seconds": 1800},
                    "rationale": "Apply provisional 30m block on LAN brute-force host",
                    "confidence": 0.92,
                },
            ]
        ]
    )
    hub = _RecordingHub()

    timeline = asyncio.run(
        run_action_loop(
            "Mitigate repeated failed logins from 192.168.1.77",
            {"role": "blue_team"},
            analyst=analyst,
            policy=policy,
            hub=hub,
            max_steps=4,
            max_rounds=1,
        )
    )
    caps = [s.proposal.action for s in timeline.steps]
    assert caps == ["threat_intel.lookup_ioc", "containment.block_ip"]
    assert timeline.steps[0].status == "completed"
    assert timeline.steps[1].status in ("completed", "awaiting_approval")

    # Emit hub notification for the containment / approval checkpoint
    env = build_notification_envelope(
        notify_type="notify.containment_applied",
        source_app="ai_for_survival",
        severity="high",
        title="Provisional block requested",
        body="Mitigation for 192.168.1.77 pending approval.",
        dedupe_key="s1:block:192.168.1.77",
    )
    asyncio.run(notifications.route(env))
    recent = notifications.recent_notifications(limit=10)
    assert any(n.get("dedupe_key") == "s1:block:192.168.1.77" for n in recent)


# ── S2: Blue Team scans an iPhone backup in an allow-listed folder ─────────

def test_s2_zbt_phone_backup_allowlist_and_redaction(tmp_path: Path, monkeypatch):
    policy, _, _ = _make_policy_stack(tmp_path)
    base_dir = tmp_path / "phone_backups"
    allowed_dir = base_dir / "iphone_backup_01"
    allowed_dir.mkdir(parents=True)
    outside_dir = tmp_path / "outside_secret_folder"
    outside_dir.mkdir(parents=True)
    monkeypatch.setenv("ECOSYSTEM_PHONE_SCAN_BASE", str(base_dir))

    reg = CapabilityRegistry()
    reg.register(SCAN_REQUEST_CAPABILITY)
    assert reg.resolve("scan.request") is not None

    # Stub metadata discovery so refusal tests never invoke a real ZBT binary on disk
    monkeypatch.setattr(ScanRunner, "_resolve_zbt_path", lambda self, *_a, **_kw: None)

    # Folder outside ECOSYSTEM_PHONE_SCAN_BASE must be refused fail-closed before ZBT starts
    runner = ScanRunner(zbt_path=tmp_path / "missing_zbt.py", data_dir=tmp_path / "data")
    denied = asyncio.run(
        runner.run_scan(
            ScanRequest(
                device_id="phone-s2",
                phone_folder=str(outside_dir),
                authorization_ref="owner-approved-s2",
            )
        )
    )
    assert denied.status == "denied"
    assert "outside the allowed ECOSYSTEM_PHONE_SCAN_BASE" in (denied.error_message or "")

    # Handler also refuses outside-base requests without leaking host paths anywhere in the response
    handler = build_scan_request_handler(ScanRunner(zbt_path=tmp_path / "missing_zbt.py", data_dir=tmp_path / "data", policy_engine=policy))
    resp = asyncio.run(
        handler(
            {
                "target": {"scope": "backup", "identifier": str(outside_dir)},
                "parameters": {"phone_folder": str(outside_dir), "profile": "quick"},
            },
            "approval:s2-owner-approval",
        )
    )
    assert resp["status"] == "denied"
    assert str(outside_dir) not in json.dumps(resp)


# ── S3: Automated brute-force triage & Freeze preemption ───────────────────

def test_s3_automated_triage_and_freeze_blocks_containment(tmp_path: Path):
    policy, _, _ = _make_policy_stack(tmp_path)
    policy.freeze(initiated_by="operator", channel="dashboard", reason="S3 freeze test")

    analyst = _scripted_analyst(
        [
            [
                {
                    "action": "containment.block_ip",
                    "action_class": "contain",
                    "target": "192.168.1.99",
                    "parameters": {"ttl_seconds": 1800},
                    "rationale": "Automated triage containment",
                    "confidence": 0.9,
                }
            ]
        ]
    )
    hub = _RecordingHub()
    timeline = asyncio.run(
        run_action_loop(
            "Brute-force alert from 192.168.1.99",
            {"source": "aegissiem"},
            analyst=analyst,
            policy=policy,
            hub=hub,
            max_steps=3,
            max_rounds=1,
        )
    )
    assert hub.dispatched == []
    assert all(s.status in ("skipped_frozen", "denied") for s in timeline.steps)


# ── S4: Refusing out-of-scope / dangerous requests ─────────────────────────

def test_s4_dangerous_system_change_denied_without_dispatch(tmp_path: Path):
    policy, _, _ = _make_policy_stack(tmp_path)
    analyst = _scripted_analyst(
        [
            [
                {
                    "action": "firewall.disable",
                    "action_class": "system_change",
                    "target": "router",
                    "parameters": {"action": "disable_firewall"},
                    "rationale": "User asked to turn off firewall",
                    "confidence": 0.9,
                }
            ]
        ]
    )
    hub = _RecordingHub()
    timeline = asyncio.run(
        run_action_loop(
            "Turn off the firewall",
            {"role": "blue_team"},
            analyst=analyst,
            policy=policy,
            hub=hub,
            max_steps=2,
            max_rounds=1,
        )
    )
    assert hub.dispatched == []
    assert len(timeline.steps) == 1
    assert timeline.steps[0].status in ("denied", "awaiting_approval")


# ── S5: Red Team assessment requires active scoped grant ───────────────────

def test_s5_red_team_scoped_grant_lifecycle(tmp_path: Path):
    policy, _, _ = _make_policy_stack(tmp_path)

    req = ActionRequest(
        actor="red-team",
        action="redteam.service_scan",
        action_class="investigate",
        target={"scope": "lab", "identifier": "192.168.50.10", "device_id": "lab-pi-1"},
        context={"app": "ai_for_survival"},
    )

    # Without a grant, Restrictions-Off override is absent
    assert policy.export_state()["restrictions"] == "on"

    # Activate time-boxed Ed25519-signed Restrictions-Off grant
    state = policy.activate_restrictions_off(
        issued_by="owner",
        auth_method="totp",
        reason="S5 authorized lab assessment",
        apps=["ai_for_survival"],
        devices=["lab-pi-1"],
        action_classes=["investigate"],
        duration_seconds=300,
        now=1000.0,
    )
    assert state["restrictions"] == "off_scoped"

    # Active within window
    d_during = policy.decide(req, now=1100.0)
    assert d_during.restrictions == "off_scoped"

    # Automatically expires after TTL
    d_after = policy.decide(req, now=1400.0)
    assert d_after.restrictions == "on"


# ── S6: Notification deduplication (OpenEye -> Hub -> MagicMirror) ─────────

def test_s6_notification_dedupe_prevents_duplicates(tmp_path: Path):
    router = NotificationRouter(persistence_path=tmp_path / "notifications.db")
    env = build_notification_envelope(
        notify_type="notify.person_detected",
        source_app="openeye",
        severity="medium",
        title="Unknown person in driveway",
        body="Detected unknown person in driveway zone.",
        dedupe_key="openeye:unknown:driveway",
    )
    first = asyncio.run(router.route(env))
    second = asyncio.run(router.route(env))
    assert first["status"] == "routed"
    assert second["status"] == "deduplicated"
    assert len(router.recent_notifications(limit=10)) == 1


# ── S7: Engage Freeze mid-loop; resume requires step-up TOTP ───────────────

def test_s7_freeze_preempts_remaining_steps_and_resume_needs_step_up(tmp_path: Path):
    policy, _, step_up = _make_policy_stack(tmp_path)
    enrolled = step_up.enroll_totp("owner")

    async def _freeze_after_first(entry: dict[str, Any]) -> dict[str, Any]:
        policy.freeze(initiated_by="magicmirror", channel="wall_display", reason="Emergency Freeze")
        return {"status": "completed", "command_id": "01WP9S70000000000000000001", "result": {"confirmed": True}}

    analyst = _scripted_analyst(
        [
            [
                {
                    "action": "threat_intel.lookup_ioc",
                    "action_class": "observe",
                    "target": "192.168.1.44",
                    "parameters": {"type": "ip"},
                    "rationale": "Step 1 lookup",
                    "confidence": 0.9,
                },
                {
                    "action": "containment.block_ip",
                    "action_class": "contain",
                    "target": "192.168.1.44",
                    "parameters": {"ttl_seconds": 1800},
                    "rationale": "Step 2 should be preempted by Freeze",
                    "confidence": 0.9,
                },
            ]
        ]
    )
    hub = _RecordingHub(on_invoke=_freeze_after_first)
    timeline = asyncio.run(
        run_action_loop(
            "Investigate and contain 192.168.1.44",
            {"role": "blue_team"},
            analyst=analyst,
            policy=policy,
            hub=hub,
            max_steps=4,
            max_rounds=1,
        )
    )
    assert len(hub.dispatched) == 1
    assert timeline.steps[1].status in ("skipped_frozen", "denied")
    assert policy.export_state()["frozen"] is True

    # Resume requires verified step-up TOTP
    code = compute_totp(enrolled["secret"], timestamp=2000.0)
    lease = step_up.verify_totp_and_issue_token("owner", code, now=2000.0)
    assert lease is not None
    resumed = policy.resume(
        operator_id=lease["operator_id"],
        auth_method=lease["auth_method"],
        reason="Verified safe to resume",
    )
    assert resumed["frozen"] is False


# ── S8: Hardware-tier analyst model selection (never tinyllama) ────────────

def test_s8_analyst_model_selection_excludes_tinyllama():
    profile = AIProfile(selected_model="auto")
    floor_passes = set(TIER_ANALYST_MODELS.values())

    for ram_gb in (4, 8, 16, 32, 64):
        hw = HardwareInfo(
            ram_gb=ram_gb,
            cpu_cores=8,
            arch="arm64",
            os_name="Darwin",
            has_gpu=False,
            vram_gb=0,
            free_disk_gb=100.0,
        )
        choice = resolve_analyst_model(profile, hw, floor_passes=floor_passes)
        assert choice
        assert "tinyllama" not in choice.lower()


# ── S9 & S10: Presence restriction safety & consent-gated scans ────────────

def test_s9_s10_freeze_blocks_restriction_and_scan_requires_consent(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(ScanRunner, "_resolve_zbt_path", lambda self, *_a, **_kw: None)
    policy, _, _ = _make_policy_stack(tmp_path)
    runner = ScanRunner(zbt_path=tmp_path / "missing_zbt.py", data_dir=tmp_path / "data", policy_engine=policy)
    handler = build_scan_request_handler(runner)

    # S10: even with owner approval passed as the second argument, a device without
    # recorded AUP consent is refused at consent enforcement before any scan starts
    unconsented = asyncio.run(
        handler(
            {
                "target": {"scope": "device", "identifier": "visitor-phone-unconsented"},
                "parameters": {
                    "target_device": "visitor-phone-unconsented",
                    "profile": "quick",
                },
            },
            "approval:s10-owner-approval",
        )
    )
    assert unconsented["status"] == "denied"

    # S9: Freeze preempts containment/restriction
    policy.freeze(initiated_by="owner", channel="dashboard", reason="S9 freeze check")
    d_restrict = policy.decide(
        ActionRequest(
            actor="openeye",
            action="access.restrict_zone",
            action_class="contain",
            target={"scope": "zone", "identifier": "office"},
            context={"app": "openeye"},
        )
    )
    assert d_restrict.result == "deny"
