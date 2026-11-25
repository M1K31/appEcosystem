"""ECO-01 tests: WebAuthn Passkey (FIDO2 ES256 / Ed25519) step-up verification."""
from __future__ import annotations

import base64
import hashlib
import json
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from fastapi.testclient import TestClient

from ecosystem_policy.step_up import StepUpAuthenticator


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _make_auth_data(rp_id: str, *, flags: int = 0x05, sign_count: int = 1) -> bytes:
    """Build a 37-byte WebAuthn authenticatorData blob (UP=0x01, UV=0x04 -> 0x05)."""
    return hashlib.sha256(rp_id.encode("utf-8")).digest() + bytes([flags]) + struct.pack(">I", sign_count)


def _make_client_data(challenge: str, *, origin: str = "http://localhost:8500", ctype: str = "webauthn.get") -> bytes:
    return json.dumps({"type": ctype, "challenge": challenge, "origin": origin}).encode("utf-8")


def test_webauthn_es256_spki_registration_verification_and_clone_detection(tmp_path: Path):
    auth = StepUpAuthenticator(store_path=tmp_path / "step_up.json", signing_secret="eco01-secret")

    # Generate a P-256 keypair (as Safari Touch ID / YubiKey produces for ES256)
    priv = ec.generate_private_key(ec.SECP256R1())
    spki_der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    reg_opts = auth.create_passkey_registration_options("admin", rp_id="localhost")
    assert reg_opts["rp"]["id"] == "localhost"
    assert reg_opts["authenticatorSelection"]["userVerification"] == "required"

    rec = auth.register_passkey(
        "admin",
        "cred-es256-001",
        public_key_spki_b64=_b64u(spki_der),
        label="MacBook Touch ID",
        rp_id="localhost",
        transports=["internal"],
    )
    assert rec["algorithm"] == "ES256"
    assert len(auth.list_passkeys("admin")) == 1

    # Valid WebAuthn assertion (UP + UV set, sign_count=1)
    auth_opts = auth.create_passkey_authentication_options("admin", rp_id="localhost")
    assert auth_opts["allowCredentials"][0]["id"] == "cred-es256-001"
    challenge = auth_opts["challenge"]
    auth_data = _make_auth_data("localhost", flags=0x05, sign_count=1)
    client_data = _make_client_data(challenge, origin="http://localhost:8500")
    sig = priv.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))

    lease = auth.verify_passkey_assertion_and_issue_token(
        "admin",
        "cred-es256-001",
        challenge,
        _b64u(sig),
        authenticator_data_b64=_b64u(auth_data),
        client_data_json_b64=_b64u(client_data),
        expected_origin="http://localhost:8500",
        expected_rp_id="localhost",
        require_user_verification=True,
    )
    assert lease is not None
    assert lease["auth_method"] == "passkey"
    assert auth.list_passkeys("admin")[0]["sign_count"] == 1

    # Clone detection: re-using sign_count=1 (<= stored 1) must be rejected
    ch2 = auth.create_passkey_authentication_options("admin", rp_id="localhost")["challenge"]
    auth_data_clone = _make_auth_data("localhost", flags=0x05, sign_count=1)
    client_data_2 = _make_client_data(ch2, origin="http://localhost:8500")
    sig2 = priv.sign(auth_data_clone + hashlib.sha256(client_data_2).digest(), ec.ECDSA(hashes.SHA256()))
    assert (
        auth.verify_passkey_assertion_and_issue_token(
            "admin",
            "cred-es256-001",
            ch2,
            _b64u(sig2),
            authenticator_data_b64=_b64u(auth_data_clone),
            client_data_json_b64=_b64u(client_data_2),
            expected_origin="http://localhost:8500",
            expected_rp_id="localhost",
            require_user_verification=True,
        )
        is None
    )


def test_webauthn_rejects_bad_origin_rpid_and_missing_uv(tmp_path: Path):
    auth = StepUpAuthenticator(store_path=tmp_path / "step_up.json", signing_secret="eco01-secret")
    priv = ed25519.Ed25519PrivateKey.generate()
    spki_der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    rec = auth.register_passkey("owner", "cred-ed25519-001", public_key_spki_b64=_b64u(spki_der))
    assert rec["algorithm"] == "ED25519"

    # 1. Plain HTTP non-loopback origin rejected
    ch1 = auth.create_passkey_authentication_options("owner", rp_id="hub.example.com")["challenge"]
    ad1 = _make_auth_data("hub.example.com", flags=0x05, sign_count=1)
    cd1 = _make_client_data(ch1, origin="http://hub.example.com")
    sig1 = priv.sign(ad1 + hashlib.sha256(cd1).digest())
    assert (
        auth.verify_passkey_assertion_and_issue_token(
            "owner",
            "cred-ed25519-001",
            ch1,
            _b64u(sig1),
            authenticator_data_b64=_b64u(ad1),
            client_data_json_b64=_b64u(cd1),
            expected_rp_id="hub.example.com",
            require_user_verification=True,
        )
        is None
    )

    # 2. Wrong rpIdHash rejected
    ch2 = auth.create_passkey_authentication_options("owner", rp_id="localhost")["challenge"]
    ad2 = _make_auth_data("evil.example", flags=0x05, sign_count=2)
    cd2 = _make_client_data(ch2, origin="https://hub.example.com")
    sig2 = priv.sign(ad2 + hashlib.sha256(cd2).digest())
    assert (
        auth.verify_passkey_assertion_and_issue_token(
            "owner",
            "cred-ed25519-001",
            ch2,
            _b64u(sig2),
            authenticator_data_b64=_b64u(ad2),
            client_data_json_b64=_b64u(cd2),
            expected_rp_id="localhost",
            require_user_verification=True,
        )
        is None
    )

    # 3. Missing UV bit (flags=0x01 only UP) rejected when require_user_verification=True
    ch3 = auth.create_passkey_authentication_options("owner", rp_id="localhost")["challenge"]
    ad3 = _make_auth_data("localhost", flags=0x01, sign_count=3)
    cd3 = _make_client_data(ch3, origin="http://localhost:8500")
    sig3 = priv.sign(ad3 + hashlib.sha256(cd3).digest())
    assert (
        auth.verify_passkey_assertion_and_issue_token(
            "owner",
            "cred-ed25519-001",
            ch3,
            _b64u(sig3),
            authenticator_data_b64=_b64u(ad3),
            client_data_json_b64=_b64u(cd3),
            expected_rp_id="localhost",
            require_user_verification=True,
        )
        is None
    )

    assert auth.remove_passkey("owner", "cred-ed25519-001") is True
    assert auth.list_passkeys("owner") == []


def test_registry_webauthn_routes_end_to_end_resume_freeze(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", "e" * 64)
    monkeypatch.setenv("ECOSYSTEM_REGISTRY_FILE", str(tmp_path / "registry.json"))
    monkeypatch.setenv("ECOSYSTEM_CAPABILITIES_FILE", str(tmp_path / "caps.json"))
    monkeypatch.setenv("ECOSYSTEM_NOTIFICATIONS_DB", str(tmp_path / "notify.db"))
    monkeypatch.setenv("ECOSYSTEM_AI_PROFILE_FILE", str(tmp_path / "ai_profile.json"))
    monkeypatch.setenv("ECOSYSTEM_POLICY_KEY_DIR", str(tmp_path / "pkeys"))
    monkeypatch.setenv("ECOSYSTEM_POLICY_STATE_FILE", str(tmp_path / "pstate.json"))
    monkeypatch.setenv("ECOSYSTEM_STEP_UP_FILE", str(tmp_path / "step_up.json"))
    monkeypatch.setenv("ECOSYSTEM_APPROVALS_DB", str(tmp_path / "approvals.db"))

    from registry.app import app

    priv = ec.generate_private_key(ec.SECP256R1())
    spki_der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with TestClient(app) as client:
        # 0. Control Plane UI exposes Passkey enrollment & verification controls
        r_ui = client.get("/ui")
        assert r_ui.status_code == 200
        assert "btnEnrollPasskey" in r_ui.text
        assert "btnVerifyPasskey" in r_ui.text
        # 1. Request registration options & register SPKI passkey
        r_opts = client.post("/auth/step-up/passkey/register/options", json={"operator_id": "admin"})
        assert r_opts.status_code == 200
        assert r_opts.json()["rp"]["id"] == "localhost"

        r_reg = client.post(
            "/auth/step-up/passkey/register",
            json={
                "operator_id": "admin",
                "credential_id": "cred-route-001",
                "public_key_spki_b64": _b64u(spki_der),
                "label": "YubiKey 5C",
            },
        )
        assert r_reg.status_code == 200

        r_list = client.get("/auth/step-up/passkey/list?operator_id=admin")
        assert r_list.status_code == 200
        assert len(r_list.json()["passkeys"]) == 1

        # 2. Freeze policy, then authenticate with passkey to obtain step_up_token and resume
        assert client.post("/policy/freeze", json={"initiated_by": "test", "reason": "ECO-01 test"}).status_code == 200

        a_opts = client.post("/auth/step-up/passkey/authenticate/options", json={"operator_id": "admin"})
        assert a_opts.status_code == 200
        challenge = a_opts.json()["challenge"]

        auth_data = _make_auth_data("localhost", flags=0x05, sign_count=1)
        client_data = _make_client_data(challenge, origin="http://localhost:8500")
        sig = priv.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))

        r_ver = client.post(
            "/auth/step-up/passkey/verify",
            headers={"Origin": "http://localhost:8500"},
            json={
                "operator_id": "admin",
                "credential_id": "cred-route-001",
                "challenge": challenge,
                "signature": _b64u(sig),
                "authenticator_data": _b64u(auth_data),
                "client_data_json": _b64u(client_data),
                "require_user_verification": True,
            },
        )
        assert r_ver.status_code == 200
        token = r_ver.json()["step_up_token"]

        r_resume = client.post(
            "/policy/resume",
            json={"step_up_token": token, "reason": "Resumed via hardware passkey"},
        )
        assert r_resume.status_code == 200
        assert r_resume.json()["frozen"] is False
