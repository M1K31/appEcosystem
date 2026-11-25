"""WP6 tests: ZBT scans as `scan.request` capability, consent, allowlist, exit codes, and notifications."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

from agents.scan_agent import (
    SCAN_REQUEST_CAPABILITY,
    ScanRequest,
    ScanRunner,
    ScanScheduler,
    ZbtMetadata,
    build_scan_request_handler,
    list_allowed_phone_folders,
)
from ecosystem_policy import PolicyEngine


def _make_fake_zbt(tmp_path: Path, *, rc: int = 0, share: dict | None = None, full: dict | None = None) -> Path:
    script = tmp_path / "fake_zbt.py"
    share_json = json.dumps(share if share is not None else {"verdict": "clean", "checked": 5})
    full_json = json.dumps(full if full is not None else {"indicators": ["/secret/path/evil.dylib", "bad-domain.example"]})
    script.write_text(
        f"""import sys, json
from pathlib import Path
if "--describe" in sys.argv:
    print(json.dumps({{
        "schema_version": "1.0",
        "tool": {{"name": "zero-breach-toolkit", "version": "1.2.3"}},
        "exit_codes": {{
            "0": "No actionable indicator matches were found and every applicable check ran.",
            "2": "Matches beyond saved references were found.",
            "3": "Scan incomplete with gaps.",
            "4": "Aborted by operator.",
            "1": "Setup or output error."
        }}
    }}))
    sys.exit(0)
if "--share-json" in sys.argv:
    idx = sys.argv.index("--share-json") + 1
    Path(sys.argv[idx]).write_text({share_json!r}, encoding="utf-8")
if "--json" in sys.argv:
    idx = sys.argv.index("--json") + 1
    Path(sys.argv[idx]).write_text({full_json!r}, encoding="utf-8")
sys.exit({rc})
""",
        encoding="utf-8",
    )
    return script


class FakeEventBus:
    def __init__(self):
        self.events: list[dict] = []

    async def publish(self, *, source: str, event_type: str, payload: dict):
        self.events.append({"source": source, "event_type": event_type, "payload": payload})


class FakeNotificationRouter:
    def __init__(self):
        self.envelopes: list[dict] = []

    async def route(self, envelope: dict):
        self.envelopes.append(envelope)


def test_exit_code_mapping_never_marks_partial_or_cancelled_clean():
    meta = ZbtMetadata.from_describe_dict({
        "exit_codes": {
            "0": "No actionable indicator matches were found and every applicable check ran.",
            "2": "Matches beyond saved references were found.",
            "3": "Incomplete run with gaps.",
            "4": "Aborted.",
            "1": "Setup or output error.",
        }
    })
    assert meta.map_wp6_outcome(0) == "clean"
    assert meta.map_wp6_outcome(2) == "findings"
    assert meta.map_wp6_outcome(3) == "partial"
    assert meta.map_wp6_outcome(4) == "partial"
    assert meta.map_wp6_outcome(1) == "unknown"
    assert meta.map_wp6_outcome(99) == "unknown"


def test_phone_folder_outside_allowlist_refused_before_zbt_starts(tmp_path: Path, monkeypatch):
    allowed = tmp_path / "allowed"
    backup_a = allowed / "iphone-backup-1"
    backup_a.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()

    monkeypatch.setenv("ECOSYSTEM_PHONE_SCAN_BASE", str(allowed))
    listed = list_allowed_phone_folders()
    assert listed["enabled"] is True
    assert [f["name"] for f in listed["folders"]] == ["iphone-backup-1"]

    # Outside folder is refused BEFORE ZBT runs
    runner = ScanRunner(zbt_path=tmp_path / "does_not_exist.py", data_dir=tmp_path / "data")
    res = asyncio.run(runner.run_scan(ScanRequest(device_id="phone-1", phone_folder=str(outside))))
    assert res.status == "denied"
    assert "outside the allowed ECOSYSTEM_PHONE_SCAN_BASE" in (res.error_message or "")


def test_consent_required_and_findings_notification_contains_no_paths_or_indicators(tmp_path: Path):
    policy = PolicyEngine(authority="standalone_local", persistence_path=tmp_path / "policy.json")
    bus = FakeEventBus()
    notifier = FakeNotificationRouter()
    zbt = _make_fake_zbt(
        tmp_path,
        rc=2,
        share={"verdict": "findings", "finding_count": 2},
        full={"indicators": ["/Users/secret/evil.dylib", "spyware-c2.example"]},
    )
    runner = ScanRunner(
        zbt_path=zbt,
        data_dir=tmp_path / "data",
        policy_engine=policy,
        event_bus=bus,
        notification_router=notifier,
    )

    # 1. Unenrolled device (no recorded AUP consent) is refused or held for approval
    denied = asyncio.run(runner.run_scan(ScanRequest(device_id="unenrolled-laptop", profile="quick")))
    assert denied.status in ("denied", "needs_approval")

    # 2. Enroll with owner + AUP consent + auto_scan designation
    policy.enroll_device("workstation-1", "fp-abc123", owner="mikel", aup_version="2.0")
    policy.designate_auto_scan("workstation-1", profiles=["quick"], initiators=["ecosystem_hub"])

    # 3. Invoke via WP6 `scan.request` command handler
    assert SCAN_REQUEST_CAPABILITY["capability"] == "scan.request"
    assert SCAN_REQUEST_CAPABILITY["action_class"] == "investigate"
    handler = build_scan_request_handler(runner)
    outcome = asyncio.run(handler({
        "capability": "scan.request",
        "target": {"scope": "local", "identifier": "workstation-1"},
        "parameters": {"target_device": "workstation-1", "profile": "quick", "offline": True, "public_key_fingerprint": "fp-abc123"},
        "actor": {"app": "ecosystem_hub", "id": "ecosystem_hub"},
    }))
    assert outcome["status"] == "completed"
    assert outcome["result"]["status"] == "findings"
    assert outcome["result"]["has_full_report"] is True
    assert "report_ref" not in outcome["result"]

    # 4. Event bus contains ONLY share.json — zero raw host filesystem paths
    assert len(bus.events) == 1
    ev_payload = bus.events[0]["payload"]
    assert "report_ref" not in ev_payload
    assert ev_payload["has_full_report"] is True
    assert ev_payload["share"]["verdict"] == "findings"

    # 5. Notification raised for findings with ZERO paths or indicator values
    assert len(notifier.envelopes) == 1
    env = notifier.envelopes[0]
    serialized_notif = json.dumps(env)
    assert env["severity"] == "high"
    assert "/Users/secret/evil.dylib" not in serialized_notif
    assert "spyware-c2.example" not in serialized_notif
    assert ".full.enc" not in serialized_notif


def test_offline_device_reports_deferred_never_clean(tmp_path: Path):
    policy = PolicyEngine(authority="standalone_local", persistence_path=tmp_path / "policy.json")
    policy.enroll_device("offline-phone", "fp-off", owner="mikel", aup_version="2.0")
    policy.designate_auto_scan("offline-phone", profiles=["quick"], initiators=["ecosystem-scan-scheduler"])

    async def always_offline(_dev_id: str) -> bool:
        return False

    runner = ScanRunner(zbt_path=_make_fake_zbt(tmp_path, rc=0), data_dir=tmp_path / "data", policy_engine=policy)
    scheduler = ScanScheduler(runner=runner, policy_engine=policy, is_device_reachable=always_offline)
    results = asyncio.run(scheduler.run_due_scans())
    assert len(results) == 1
    assert results[0].status == "deferred"
    assert results[0].status != "clean"
