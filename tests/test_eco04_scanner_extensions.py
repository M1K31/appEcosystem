"""ECO-04 tests: Pluggable ZBT Scanner Extension Framework."""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agents.scan_agent import (
    ExtensionContext,
    ExtensionResult,
    ScanRequest,
    ScanRunner,
    ScannerExtensionRegistry,
    ScriptScannerExtension,
)


def _make_fake_zbt(tmp_path: Path, *, rc: int = 0) -> Path:
    script = tmp_path / "fake_zbt.py"
    script.write_text(
        f"""
import json, sys
from pathlib import Path
if "--describe" in sys.argv:
    print(json.dumps({{"exit_codes": {{"0": "Clean", "2": "Findings", "3": "Partial"}}}}))
    sys.exit(0)
if "--share-json" in sys.argv:
    Path(sys.argv[sys.argv.index("--share-json") + 1]).write_text(
        json.dumps({{"verdict": "clean", "finding_count": 0}}), encoding="utf-8"
    )
if "--json" in sys.argv:
    Path(sys.argv[sys.argv.index("--json") + 1]).write_text(
        json.dumps({{"core": "clean"}}), encoding="utf-8"
    )
sys.exit({rc})
""",
        encoding="utf-8",
    )
    return script


def test_callable_extension_escalates_findings_and_keeps_details_encrypted(tmp_path: Path):
    reg = ScannerExtensionRegistry()
    reg.register_callable(
        "ios-profile-audit",
        lambda ctx: ExtensionResult(
            extension_id="ios-profile-audit",
            status="findings",
            findings_count=1,
            severity="high",
            summary="Suspicious MDM profile at /Users/alice/private/profile.mobileconfig",
            details={"secret_ioc": "evil-mdm.example", "raw_path": "/Users/alice/private"},
        ),
        display_name="iOS Configuration Profile Auditor",
        profiles=("quick", "full"),
    )
    reg.register_callable(
        "full-only-check",
        lambda ctx: ExtensionResult(extension_id="full-only-check", status="findings", findings_count=9),
        profiles=("full",),
    )

    runner = ScanRunner(
        zbt_path=_make_fake_zbt(tmp_path, rc=0),
        data_dir=tmp_path / "data",
        extension_registry=reg,
    )
    res = asyncio.run(runner.run_scan(ScanRequest(device_id="local", profile="quick")))

    # Findings from extension escalate clean ZBT run to 'findings'
    assert res.status == "findings"
    # Profile filtering: full-only-check did NOT run on 'quick'
    exts = res.share["extensions"]
    assert len(exts) == 1
    assert exts[0]["extension_id"] == "ios-profile-audit"
    # Bus/share summary redacts host paths and omits sensitive details
    assert "/Users/alice" not in json.dumps(res.share)
    assert "evil-mdm.example" not in json.dumps(res.share)

    # Full details are preserved inside the AES-256-GCM encrypted report
    full = runner.decrypt_full_report(res.scan_id)
    assert full["extensions"][0]["details"]["secret_ioc"] == "evil-mdm.example"


def test_failing_extension_isolates_error_and_marks_scan_partial(tmp_path: Path):
    reg = ScannerExtensionRegistry()

    def _boom(_ctx: ExtensionContext) -> ExtensionResult:
        raise RuntimeError("boom /secret/path/crash")

    reg.register_callable("crashing-check", _boom)
    runner = ScanRunner(
        zbt_path=_make_fake_zbt(tmp_path, rc=0),
        data_dir=tmp_path / "data",
        extension_registry=reg,
    )
    res = asyncio.run(runner.run_scan(ScanRequest(device_id="local", profile="quick")))
    assert res.status == "partial"
    assert res.share["extensions"][0]["status"] == "error"
    assert "/secret/path" not in json.dumps(res.share)


def test_script_extension_scrubs_env_and_enforces_dir_and_sha256(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", "super-secret-must-not-leak")
    ext_dir = tmp_path / "extensions"
    ext_dir.mkdir()
    script = ext_dir / "check_env.py"
    script.write_text(
        """
import json, os, sys
leaked = "ECOSYSTEM_HMAC_SECRET" in os.environ
print(json.dumps({
    "status": "findings" if leaked else "clean",
    "findings_count": 1 if leaked else 0,
    "severity": "critical" if leaked else "low",
    "summary": "env check complete",
    "details": {"readonly_flag": os.environ.get("ECOSYSTEM_EXTENSION_READONLY")},
}))
""",
        encoding="utf-8",
    )
    digest = hashlib.sha256(script.read_bytes()).hexdigest()

    # Path outside extensions_dir is refused
    outside = tmp_path / "outside.py"
    outside.write_text("print('{}')", encoding="utf-8")
    with pytest.raises(ValueError, match="outside allowed extensions_dir"):
        ScriptScannerExtension("bad-ext", outside, extensions_dir=ext_dir)

    # Wrong SHA-256 is refused
    with pytest.raises(PermissionError, match="SHA-256 mismatch"):
        ScriptScannerExtension("bad-hash", script, extensions_dir=ext_dir, expected_sha256="0" * 64)

    # Valid pinned script runs with scrubbed env (ECOSYSTEM_HMAC_SECRET absent)
    ext = ScriptScannerExtension("env-audit", script, extensions_dir=ext_dir, expected_sha256=digest)
    res = asyncio.run(
        ext.run(ExtensionContext(scan_id="s1", device_id="local", profile="quick", offline=True))
    )
    assert res.status == "clean"
    assert res.details["readonly_flag"] == "1"


def test_scans_extensions_route_lists_registered_extensions(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", "x" * 64)
    monkeypatch.setenv("ECOSYSTEM_REGISTRY_FILE", str(tmp_path / "registry.json"))
    monkeypatch.setenv("ECOSYSTEM_CAPABILITIES_FILE", str(tmp_path / "caps.json"))
    monkeypatch.setenv("ECOSYSTEM_NOTIFICATIONS_DB", str(tmp_path / "notify.db"))
    monkeypatch.setenv("ECOSYSTEM_AI_PROFILE_FILE", str(tmp_path / "ai_profile.json"))
    monkeypatch.setenv("ECOSYSTEM_POLICY_KEY_DIR", str(tmp_path / "pkeys"))
    monkeypatch.setenv("ECOSYSTEM_POLICY_STATE_FILE", str(tmp_path / "pstate.json"))
    monkeypatch.setenv("ECOSYSTEM_STEP_UP_FILE", str(tmp_path / "step_up.json"))
    monkeypatch.setenv("ECOSYSTEM_APPROVALS_DB", str(tmp_path / "approvals.db"))
    monkeypatch.setenv("ECOSYSTEM_PAIRING_DIR", str(tmp_path / "pairing"))

    from registry.app import app

    with TestClient(app) as client:
        app.state.scan_runner.extension_registry.register_callable(
            "custom-check",
            lambda _ctx: ExtensionResult(extension_id="custom-check", status="clean"),
            display_name="Custom Check",
        )
        r = client.get("/scans/extensions")
        assert r.status_code == 200
        assert r.json()["extensions"][0]["extension_id"] == "custom-check"
