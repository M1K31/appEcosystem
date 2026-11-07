"""Phase 3 tests: `ecosystem-policy`, Ed25519 overrides, Freeze preemption, step-up auth, unified approvals, and Hub Control Plane UI."""
from __future__ import annotations

import base64
import hashlib
import json
import time

import pytest
import yaml
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from fastapi.testclient import TestClient

from ecosystem_policy import (
    ActionRequest,
    Ed25519PolicySigner,
    LocalApprovalQueue,
    PolicyEngine,
    StepUpAuthenticator,
    compute_totp,
)


def test_ed25519_policy_signing_and_tampered_yaml_fail_closed(tmp_path):
    signer = Ed25519PolicySigner.load_or_create(tmp_path / "keys")
    custom_doc = {
        "version": 9,
        "defaults": {
            "posture": "blue_team",
            "observe": "allow",
            "investigate": "require_approval",
            "contain": {"decision": "allow_and_notify", "approval": "async", "ttl": "1h", "on_deny": "revert"},
            "remediate": "require_approval",
            "data_release": "require_approval",
            "system_change": "require_approval",
        },
    }
    signed = signer.sign_dict(custom_doc)
    assert signer.verify_dict(signed) is True

    valid_path = tmp_path / "valid_policy.yaml"
    valid_path.write_text(yaml.safe_dump(signed), encoding="utf-8")
    eng_ok = PolicyEngine.load(valid_path, signer=signer)
    assert eng_ok.policy_version == 9

    # Tamper with version without re-signing -> must fail closed to default version 3
    tampered = dict(signed)
    tampered["version"] = 99
    bad_path = tmp_path / "tampered_policy.yaml"
    bad_path.write_text(yaml.safe_dump(tampered), encoding="utf-8")
    eng_bad = PolicyEngine.load(bad_path, signer=signer)
    assert eng_bad.policy_version == 3


def test_blue_team_defaults_freeze_preemption_and_always_enforced_boundaries():
    eng = PolicyEngine(authority="hub_synced")
    t0 = 1_750_000_000.0
    eng.enroll_device("mbp-01", "fp-mbp-01-ed25519", owner="mikel", now=t0 - 100)

    # 1. Blue-team defaults
    assert eng.decide(ActionRequest("cyber-agents/triage", "read_syslog", "observe"), now=t0).result == "allow"
    d_rem = eng.decide(ActionRequest("cyber-agents/triage", "wipe_host", "remediate", {"device_id": "mbp-01"}), now=t0)
    assert d_rem.result == "require_approval"

    d_con = eng.decide(ActionRequest("aegissiem/pipeline", "block_ip", "contain", {"ip": "203.0.113.9"}), now=t0)
    assert d_con.result == "allow_and_notify"
    assert d_con.async_approval is True
    assert d_con.on_deny == "revert"
    assert d_con.revert_plan == {"action": "revert_block_ip", "target": {"ip": "203.0.113.9"}}

    # 2. Scoped Ed25519 Restrictions: Off grant permits in-scope remediate
    state_off = eng.activate_restrictions_off(
        issued_by="admin",
        auth_method="totp",
        reason="Authorized incident exercise",
        apps=["cyber-agents"],
        devices=["*"],
        action_classes=["remediate", "investigate"],
        duration_seconds=1800,
        now=t0,
    )
    assert state_off["restrictions"] == "off_scoped"
    d_rem_off = eng.decide(
        ActionRequest("cyber-agents/triage", "stop_process", "remediate", {"device_id": "mbp-01"}),
        now=t0 + 10,
    )
    assert d_rem_off.result == "allow_and_notify"
    assert d_rem_off.grant_id == state_off["active_override"]["grant_id"]

    # 3. Always-enforced boundaries CANNOT be bypassed by Restrictions: Off:
    # 3a. Out-of-scope app
    assert (
        eng.decide(ActionRequest("openeye/rule", "stop_process", "remediate", {"device_id": "mbp-01"}), now=t0 + 10).result
        == "require_approval"
    )
    # 3b. External active recon without target authorization
    assert (
        eng.decide(
            ActionRequest("cyber-agents/recon", "active_port_scan", "investigate", {"external_ip": "198.51.100.44"}),
            now=t0 + 10,
        ).result
        == "deny"
    )
    # 3c. Sensitive cloud egress without approved data_release
    assert (
        eng.decide(
            ActionRequest(
                "cyber-agents/llm",
                "upload_router_logs",
                "data_release",
                {"destination": "cloud_gpu", "classification": "sensitive"},
            ),
            now=t0 + 10,
        ).result
        == "require_approval"
    )
    # 3d. Newly joined device enrolled AFTER override grant issuance does NOT inherit wildcard grant
    eng.enroll_device("late-laptop-02", "fp-late-02", owner="mikel", now=t0 + 50)
    assert (
        eng.decide(
            ActionRequest("cyber-agents/triage", "stop_process", "remediate", {"device_id": "late-laptop-02"}),
            now=t0 + 60,
        ).result
        == "require_approval"
    )

    # 4. FREEZE PREEMPTION: Freeze immediately overrides Restrictions: Off!
    state_frozen = eng.freeze(initiated_by="magicmirror", channel="magicmirror_voice", reason="Voice freeze")
    assert state_frozen["frozen"] is True
    assert state_frozen["mode"] == "freeze"
    assert (
        eng.decide(
            ActionRequest("cyber-agents/triage", "stop_process", "remediate", {"device_id": "mbp-01"}),
            now=t0 + 70,
        ).result
        == "deny"
    )
    # Passive observe remains allowed during Freeze
    assert eng.decide(ActionRequest("aegissiem/monitor", "tail_logs", "observe"), now=t0 + 70).result == "allow"

    # Resume requires step-up auth
    with pytest.raises(PermissionError):
        eng.resume(operator_id="wall-panel", auth_method="ambient")
    eng.resume(operator_id="admin", auth_method="passkey")
    assert eng.frozen is False

    # 5. Lease expiry fails closed and disables Restrictions: Off
    eng.set_authority("lease_expired")
    assert eng.export_state(now=t0 + 80)["restrictions"] == "on"
    assert (
        eng.decide(
            ActionRequest("cyber-agents/triage", "stop_process", "remediate", {"device_id": "mbp-01"}),
            now=t0 + 80,
        ).result
        == "require_approval"
    )


def test_auto_scan_device_key_grant_dhcp_immunity_and_revocation():
    eng = PolicyEngine()
    t0 = 1_750_000_000.0
    eng.enroll_device("workstation-1", "fp-real-key-abc", owner="mikel", now=t0)
    eng.designate_auto_scan("workstation-1", profiles=["quick", "standard"])

    # Valid key + permitted profile -> allow_and_notify
    ok_dec = eng.decide(
        ActionRequest(
            "openeye/automation",
            "zbt_scan",
            "investigate",
            {"device_id": "workstation-1", "public_key_fingerprint": "fp-real-key-abc"},
            context={"profile": "quick"},
        ),
        now=t0 + 5,
    )
    assert ok_dec.result == "allow_and_notify"

    # DHCP IP reused by a different physical device (different public key fingerprint) -> DENY!
    dhcp_spoof = eng.decide(
        ActionRequest(
            "openeye/automation",
            "zbt_scan",
            "investigate",
            {"device_id": "workstation-1", "public_key_fingerprint": "fp-rogue-device-xyz"},
            context={"profile": "quick"},
        ),
        now=t0 + 5,
    )
    assert dhcp_spoof.result == "deny"

    # Profile not in grant ('deep' not in ['quick', 'standard']) -> require_approval
    deep_dec = eng.decide(
        ActionRequest(
            "openeye/automation",
            "zbt_scan",
            "investigate",
            {"device_id": "workstation-1", "public_key_fingerprint": "fp-real-key-abc"},
            context={"profile": "deep"},
        ),
        now=t0 + 5,
    )
    assert deep_dec.result == "require_approval"

    # Revoking grant immediately stops automatic scans
    assert eng.revoke_auto_scan("workstation-1") is True
    revoked_dec = eng.decide(
        ActionRequest(
            "openeye/automation",
            "zbt_scan",
            "investigate",
            {"device_id": "workstation-1", "public_key_fingerprint": "fp-real-key-abc"},
            context={"profile": "quick"},
        ),
        now=t0 + 10,
    )
    assert revoked_dec.result == "require_approval"


def test_step_up_totp_passkey_and_approval_queue_revert(tmp_path):
    secret_hmac = "b" * 64
    su = StepUpAuthenticator(tmp_path / "step_up.json", signing_secret=secret_hmac)
    enrolled = su.enroll_totp("admin")
    t0 = 1_750_000_200.0
    code = compute_totp(enrolled["secret"], timestamp=t0)

    tok_res = su.verify_totp_and_issue_token("admin", code, now=t0)
    assert tok_res is not None
    # Replay in same 30s window must fail
    assert su.verify_totp_and_issue_token("admin", code, now=t0 + 2) is None

    # ES256 WebAuthn Passkey registration & full authenticatorData + clientDataJSON assertion
    ec_priv = ec.generate_private_key(ec.SECP256R1())
    ec_pub_pem = ec_priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    su.register_passkey("admin", "cred-es256-1", ec_pub_pem, algorithm="ES256")
    ch = su.create_challenge("admin")
    auth_data = b"\x01" * 37
    client_data = json.dumps({"type": "webauthn.get", "challenge": ch["challenge"], "origin": "http://localhost:8500"}).encode("utf-8")
    sig = ec_priv.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
    pk_res = su.verify_passkey_assertion_and_issue_token(
        "admin",
        "cred-es256-1",
        ch["challenge"],
        base64.urlsafe_b64encode(sig).decode("ascii").rstrip("="),
        authenticator_data_b64=base64.urlsafe_b64encode(auth_data).decode("ascii").rstrip("="),
        client_data_json_b64=base64.urlsafe_b64encode(client_data).decode("ascii").rstrip("="),
    )
    assert pk_res is not None
    assert pk_res["auth_method"] == "passkey"

    # Approval queue: unauthenticated caller rejected; deny & TTL expiry trigger containment revert
    reverted: list[dict] = []
    q = LocalApprovalQueue(tmp_path / "approvals.db", step_up=su, revert_callback=lambda r: reverted.append(r))

    c1 = q.request_approval(
        requester_service="aegissiem",
        actor="aegissiem/firewall",
        action="block_ip",
        action_class="contain",
        target={"ip": "198.51.100.77"},
        ttl_seconds=60,
        async_containment=True,
        on_deny="revert",
        revert_plan={"action": "unblock_ip", "ip": "198.51.100.77"},
        now=t0,
    )
    with pytest.raises(PermissionError):
        q.approve(c1["approval_id"])

    denied = q.deny(c1["approval_id"], step_up_token=pk_res["step_up_token"], now=t0 + 5)
    assert denied["status"] == "denied"
    assert denied["reverted"] is True
    assert len(reverted) == 1

    # Second async containment expires via TTL -> auto-reverts
    c2 = q.request_approval(
        requester_service="aegissiem",
        actor="aegissiem/firewall",
        action="quarantine_device",
        action_class="contain",
        target={"device_id": "iot-cam-3"},
        ttl_seconds=30,
        async_containment=True,
        on_deny="revert",
        revert_plan={"action": "unquarantine_device", "device_id": "iot-cam-3"},
        now=t0,
    )
    expired = q.expire_due(now=t0 + 45)
    assert len(expired) == 1
    assert expired[0]["approval_id"] == c2["approval_id"]
    assert expired[0]["reverted"] is True
    assert len(reverted) == 2


def test_hub_control_plane_routes_and_ui(monkeypatch, tmp_path):
    secret = "c" * 64
    monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", secret)
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
        # Control Plane UI & assets
        r_ui = client.get("/ui")
        assert r_ui.status_code == 200
        assert "<ecosystem-policy-bar" in r_ui.text
        assert client.get("/ui/ecosystem-theme.css").status_code == 200
        assert client.get("/ui/ecosystem-ui-controls.js").status_code == 200

        # Policy state conforms to policy-state.v1
        st = client.get("/policy/state").json()
        assert st["schema_version"] == 1
        assert st["restrictions"] == "on"
        assert st["frozen"] is False

        # Enroll TOTP and test Freeze -> unauthenticated Resume fails -> TOTP Resume succeeds
        totp_info = client.post("/auth/step-up/totp/enroll", json={"operator_id": "admin"}).json()
        totp_secret = totp_info["secret"]

        fr = client.post("/policy/freeze", json={"initiated_by": "openeye", "reason": "Test freeze"})
        assert fr.status_code == 200
        assert fr.json()["frozen"] is True

        assert client.post("/policy/resume", json={}).status_code == 401
        code = compute_totp(totp_secret)
        # Exchange the TOTP code for a reusable step-up token once (consuming a
        # single TOTP window) and reuse it for both resume and the later passkey
        # registration — registering a 2nd factor now requires proven step-up.
        step_up_token = client.post(
            "/auth/step-up/totp/verify", json={"operator_id": "admin", "code": code}
        ).json()["step_up_token"]
        resumed = client.post("/policy/resume", json={"step_up_token": step_up_token})
        assert resumed.status_code == 200
        assert resumed.json()["frozen"] is False

        # Create approval via /policy/decide and approve with fresh TOTP token
        dec = client.post(
            "/policy/decide",
            json={
                "actor": "cyber-agents/hunter",
                "action": "permanent_firewall_drop",
                "action_class": "remediate",
                "target": {"ip": "198.51.100.88"},
                "enqueue_approval": True,
            },
        )
        assert dec.status_code == 200
        approval_id = dec.json()["approval"]["approval_id"]

        # Unauthenticated approve rejected
        assert client.post(f"/approvals/{approval_id}/approve", json={}).status_code == 401

        # Issue step-up token via Ed25519 device key (iOS Shortcut simulation)
        ed_priv = ed25519.Ed25519PrivateKey.generate()
        ed_pub_b64 = base64.urlsafe_b64encode(
            ed_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ).decode("ascii").rstrip("=")
        reg_r = client.post(
            "/auth/step-up/passkey/register",
            json={
                "operator_id": "admin",
                "credential_id": "ios-shortcut-1",
                "public_key": ed_pub_b64,
                "algorithm": "ED25519",
                "label": "iOS Shortcut Key",
                "step_up_token": step_up_token,
            },
        )
        assert reg_r.status_code == 200
        ch = client.post("/auth/step-up/passkey/challenge", json={"operator_id": "admin"}).json()["challenge"]
        sig_b64 = base64.urlsafe_b64encode(ed_priv.sign(ch.encode("ascii"))).decode("ascii").rstrip("=")
        verify_r = client.post(
            "/auth/step-up/passkey/verify",
            json={
                "operator_id": "admin",
                "credential_id": "ios-shortcut-1",
                "challenge": ch,
                "signature": sig_b64,
            },
        )
        assert verify_r.status_code == 200
        step_token = verify_r.json()["step_up_token"]

        ap_r = client.post(
            f"/approvals/{approval_id}/approve",
            headers={"X-Ecosystem-Step-Up": step_token},
            json={"note": "Approved via signed device key"},
        )
        assert ap_r.status_code == 200
        assert ap_r.json()["status"] == "approved"
        assert ap_r.json()["auth_method"] == "device_key"

