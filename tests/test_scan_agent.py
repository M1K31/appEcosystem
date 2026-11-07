"""Unit tests for Phase 4 Scan Agent (ZBT wrapper, encryption at rest, PolicyEngine gating, scheduler, and API)."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from agents.scan_agent import (
    ScanReportEncryptor,
    ScanRequest,
    ScanResult,
    ScanRunner,
    ScanScheduler,
    ZbtMetadata,
)
from ecosystem_policy.crypto import Ed25519PolicySigner
from ecosystem_policy.engine import PolicyEngine
from ecosystem_policy.step_up import StepUpAuthenticator


def test_zbt_metadata_dynamic_mapping():
    describe_data = {
        "schema_version": "1.6",
        "tool": {"name": "zero-breach-toolkit", "version": "2.0.2"},
        "exit_codes": {
            "0": "No actionable indicator matches were found, and every applicable check in the selected scope ran.",
            "1": "A setup or output error occurred.",
            "2": "Indicator matches beyond saved references were found.",
            "3": "No actionable indicator matches were found, but checks or indicator sources were incomplete.",
            "4": "The person left the start menu without running a check.",
        },
        "content_trust": {"untrusted_fields": ["modules.*.hits[].location"]},
        "instructions_for_assistants": ["Relay every item in must_relay to the person, in full"],
    }
    meta = ZbtMetadata.from_describe_dict(describe_data)
    assert meta.schema_version == "1.6"
    assert meta.tool_name == "zero-breach-toolkit"
    assert meta.tool_version == "2.0.2"
    assert meta.map_exit_code(0) == "clean"
    assert meta.map_exit_code(1) == "error"
    assert meta.map_exit_code(2) == "findings"
    assert meta.map_exit_code(3) == "gaps"
    assert meta.map_exit_code(4) == "aborted"
    assert meta.map_exit_code(99) == "unknown"


def test_scan_report_encryptor(tmp_path: Path):
    key_path = tmp_path / "keystore" / "scan_enc.key"
    encryptor = ScanReportEncryptor(key_path)

    assert key_path.is_file()
    # Check permissions
    mode = oct(key_path.stat().st_mode & 0o777)
    assert mode == "0o600"

    plain = b'{"secret": "sensitive forensic path /Users/victim/foo"}'
    token = encryptor.encrypt_bytes(plain)
    assert token != plain
    assert b"victim" not in token

    decrypted = encryptor.decrypt_bytes(token)
    assert decrypted == plain


@pytest.mark.asyncio
async def test_scan_runner_policy_freeze_blocks(tmp_path: Path):
    signer = Ed25519PolicySigner.generate()
    policy = PolicyEngine({}, signer=signer, persistence_path=tmp_path / "p_state.json")
    policy.freeze(initiated_by="operator", reason="Emergency test freeze")

    runner = ScanRunner(
        data_dir=tmp_path / "data",
        policy_engine=policy,
        keystore_dir=tmp_path / "keys",
    )

    req = ScanRequest(device_id="local", profile="quick")
    result = await runner.run_scan(req)

    assert result.status == "denied"
    assert "Ecosystem Freeze is active" in result.exit_description
    assert result.report_ref == ""


@pytest.mark.asyncio
async def test_scan_runner_single_flight_lock(tmp_path: Path):
    runner = ScanRunner(
        data_dir=tmp_path / "data",
        keystore_dir=tmp_path / "keys",
    )
    # Manually hold lock on device_id="node-1"
    lock = runner._get_device_lock("node-1")
    await lock.acquire()

    req = ScanRequest(device_id="node-1", profile="quick")
    result = await runner.run_scan(req)

    assert result.status == "deferred"
    assert "Device busy" in (result.error_message or "")
    lock.release()


@pytest.mark.asyncio
async def test_scan_runner_mock_execution(tmp_path: Path):
    # Create mock ZBT script
    mock_zbt = tmp_path / "mock_zbt.py"
    mock_zbt.write_text("""
import sys, json
from pathlib import Path

args = sys.argv[1:]
if "--describe" in args:
    print(json.dumps({
        "schema_version": "1.6",
        "tool": {"name": "mock-zbt", "version": "1.0.0"},
        "exit_codes": {"0": "No actionable indicator matches were found, and every applicable check ran."}
    }))
    sys.exit(0)

# Parse output paths
json_idx = args.index("--json")
share_idx = args.index("--share-json")
json_path = Path(args[json_idx + 1])
share_path = Path(args[share_idx + 1])

json_path.write_text(json.dumps({"full_details": ["/Users/admin/passwords.txt", "spyware trace"]}))
share_path.write_text(json.dumps({"verdict": "clean", "checks_run": 10}))
sys.exit(0)
""")

    signer = Ed25519PolicySigner.generate()
    policy = PolicyEngine({}, signer=signer, persistence_path=tmp_path / "p_state.json")
    event_bus = MagicMock()
    event_bus.publish = AsyncMock()

    runner = ScanRunner(
        zbt_path=mock_zbt,
        data_dir=tmp_path / "data",
        policy_engine=policy,
        event_bus=event_bus,
        keystore_dir=tmp_path / "keys",
    )

    req = ScanRequest(device_id="local", profile="quick")
    result = await runner.run_scan(req)

    assert result.status == "clean"
    assert result.exit_code == 0
    assert result.share.get("verdict") == "clean"
    assert result.report_ref != ""
    assert Path(result.report_ref).is_file()

    # Plaintext full.json must not exist
    out_dir = Path(result.report_ref).parent
    assert not (out_dir / "full.json").exists()

    # Event bus should have published scan.completed with share only
    event_bus.publish.assert_called_once()
    call_kwargs = event_bus.publish.call_args.kwargs
    assert call_kwargs["event_type"] == "scan.completed"
    assert call_kwargs["payload"]["share"]["verdict"] == "clean"
    assert "full_details" not in call_kwargs["payload"]["share"]

    # Decrypt full report
    decrypted = runner.decrypt_full_report(result.scan_id)
    assert "full_details" in decrypted
    assert "/Users/admin/passwords.txt" in decrypted["full_details"]


@pytest.mark.asyncio
async def test_scan_scheduler(tmp_path: Path):
    signer = Ed25519PolicySigner.generate()
    policy = PolicyEngine({}, signer=signer, persistence_path=tmp_path / "p_state.json")

    # Enroll device 1 with auto_scan grant
    policy.enroll_device(
        device_id="dev-1",
        public_key_fingerprint="fp1",
        owner="admin",
    )
    policy.designate_auto_scan(
        device_id="dev-1",
        profiles=["quick"],
        authorization_ref="admin-designation",
    )

    # Enroll device 2 without grant
    policy.enroll_device(
        device_id="dev-2",
        public_key_fingerprint="fp2",
        owner="admin",
    )

    runner = ScanRunner(data_dir=tmp_path / "data", policy_engine=policy, keystore_dir=tmp_path / "keys")
    runner.run_scan = AsyncMock(return_value=ScanResult(
        scan_id="s1",
        device_id="dev-1",
        status="clean",
        exit_code=0,
        exit_description="Clean",
        share={"verdict": "clean"},
        report_ref="",
        started_at="",
        completed_at="",
        duration_seconds=1.0,
    ))

    # Mock reachability: dev-1 is reachable, dev-2 is reachable
    async def is_reachable(dev_id: str) -> bool:
        return True

    scheduler = ScanScheduler(runner=runner, policy_engine=policy, is_device_reachable=is_reachable)
    targets = await scheduler.check_enrolled_targets()

    assert len(targets) == 2
    dev1_info = next(t for t in targets if t["device_id"] == "dev-1")
    dev2_info = next(t for t in targets if t["device_id"] == "dev-2")

    assert dev1_info["status"] == "eligible"
    assert dev1_info["auto_scan_authorized"] is True
    assert dev2_info["status"] == "unauthorized"
    assert dev2_info["auto_scan_authorized"] is False

    executed = await scheduler.run_due_scans()
    assert len(executed) == 1
    assert executed[0].device_id == "dev-1"


def test_scan_routes_and_step_up_decrypt(tmp_path: Path):
    from fastapi import FastAPI
    from registry.scan_routes import router as scan_router

    signer = Ed25519PolicySigner.generate()
    policy = PolicyEngine({}, signer=signer, persistence_path=tmp_path / "p_state.json")
    step_up = StepUpAuthenticator(store_path=tmp_path / "step_up.json")
    totp_setup = step_up.enroll_totp("operator1", issuer="AppEcosystemTest")
    secret = totp_setup["secret"]

    from ecosystem_policy.step_up import compute_totp
    valid_totp = compute_totp(secret)

    # Create dummy scan record with encrypted file
    ks_dir = tmp_path / "keys"
    runner = ScanRunner(data_dir=tmp_path / "data", policy_engine=policy, keystore_dir=ks_dir)
    scan_id = "test-scan-123"
    enc_path = tmp_path / "data" / "scans" / scan_id / f"{scan_id}.full.enc"
    enc_path.parent.mkdir(parents=True, exist_ok=True)
    plain_data = json.dumps({"classified_findings": ["malware.exe"]}).encode("utf-8")
    enc_bytes = runner.encryptor.encrypt_bytes(plain_data)
    enc_path.write_bytes(enc_bytes)

    dummy_result = ScanResult(
        scan_id=scan_id,
        device_id="local",
        status="findings",
        exit_code=2,
        exit_description="Matches found",
        share={"verdict": "findings", "count": 1},
        report_ref=str(enc_path),
        started_at="2026-11-01T20:00:00Z",
        completed_at="2026-11-01T20:01:00Z",
        duration_seconds=60.0,
    )
    runner._results_history[scan_id] = dummy_result

    sched = ScanScheduler(runner=runner, policy_engine=policy)

    app = FastAPI()
    app.state.scan_runner = runner
    app.state.scan_scheduler = sched
    app.state.policy_engine = policy
    app.state.step_up_auth = step_up
    app.include_router(scan_router)

    client = TestClient(app)

    # 1. GET /scans
    r = client.get("/scans")
    assert r.status_code == 200
    scans = r.json()
    assert len(scans) == 1
    assert scans[0]["scan_id"] == scan_id

    # 2. GET /scans/{id}
    r = client.get(f"/scans/{scan_id}")
    assert r.status_code == 200
    assert r.json()["share"]["verdict"] == "findings"

    # 3. GET /scans/{id}/full without step-up auth should be 401
    r = client.get(f"/scans/{scan_id}/full")
    assert r.status_code == 401

    # 4. GET /scans/{id}/full with valid TOTP code
    r = client.get(
        f"/scans/{scan_id}/full",
        headers={"X-Ecosystem-TOTP": valid_totp},
        params={"operator_id": "operator1"},
    )
    assert r.status_code == 200
    full_report = r.json()
    assert "classified_findings" in full_report
    assert full_report["classified_findings"] == ["malware.exe"]
