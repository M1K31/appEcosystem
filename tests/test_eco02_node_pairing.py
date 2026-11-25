"""ECO-02 tests: Cryptographic Node Auto-Pairing (mDNS + ECDSA P-256 pinning + ECDH/AES-GCM)."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ecosystem_policy.step_up import compute_totp
from registry.discovery import EcosystemDiscovery
from registry.pairing import (
    NodePairingManager,
    compute_sas_code,
    decrypt_paired_secret,
    generate_ecdsa_keypair,
    sign_claim_proof,
)


def test_ecdsa_node_pairing_round_trip_and_mitm_rejection(tmp_path: Path):
    mgr = NodePairingManager(data_dir=tmp_path / "pairing")
    node_priv, node_pub_pem = generate_ecdsa_keypair()
    secret = "eco02-super-secret-hmac-key-0123456789abcdef"

    # 1. Node submits pairing request
    req = mgr.request_pairing(
        node_id="edge-pi-garage",
        public_key_pem=node_pub_pem,
        hostname="garage-pi.local",
        roles=["edge_sensor", "openeye"],
        now=1000.0,
    )
    pairing_id = req["pairing_id"]
    assert req["hub_fingerprint"] == mgr.hub_fingerprint

    # Both hub and node independently derive the identical 6-digit SAS
    node_derived_sas = compute_sas_code(req["hub_public_key_pem"], node_pub_pem, pairing_id)
    assert node_derived_sas == req["sas_code"]
    assert len(node_derived_sas) == 6 and node_derived_sas.isdigit()

    # 2. Wrong SAS is rejected and invalidates the pending request (single-attempt MITM protection)
    with pytest.raises(PermissionError, match="SAS code mismatch"):
        mgr.approve_pairing(
            pairing_id,
            secret_value=secret,
            approved_by="owner",
            expected_sas="000000" if node_derived_sas != "000000" else "999999",
            expected_fingerprint=req["node_fingerprint"],
            now=1010.0,
        )

    # Create a fresh request after invalidation, then approve with matching SAS + fingerprint
    req = mgr.request_pairing(
        node_id="edge-pi-garage",
        public_key_pem=node_pub_pem,
        hostname="garage-pi.local",
        roles=["edge_sensor", "openeye"],
        now=1015.0,
    )
    pairing_id = req["pairing_id"]
    node_derived_sas = compute_sas_code(req["hub_public_key_pem"], node_pub_pem, pairing_id)

    # 3. Matching SAS + fingerprint pins the node's ECDSA public key and encrypts the secret
    approved = mgr.approve_pairing(
        pairing_id,
        secret_value=secret,
        approved_by="owner",
        expected_sas=node_derived_sas,
        expected_fingerprint=req["node_fingerprint"],
        now=1020.0,
    )
    assert approved["status"] == "approved"
    assert len(mgr.list_paired_nodes()) == 1

    # 4. Wrong key cannot claim the encrypted bundle
    attacker_priv, _ = generate_ecdsa_keypair()
    forged_sig = sign_claim_proof(attacker_priv, pairing_id, "edge-pi-garage")
    with pytest.raises(PermissionError, match="proof-of-possession"):
        mgr.claim_pairing(pairing_id, node_id="edge-pi-garage", signature_b64=forged_sig, now=1030.0)

    # 5. Legitimate node proves possession and decrypts the exact ecosystem secret
    valid_sig = sign_claim_proof(node_priv, pairing_id, "edge-pi-garage")
    claimed = mgr.claim_pairing(pairing_id, node_id="edge-pi-garage", signature_b64=valid_sig, now=1035.0)
    recovered = decrypt_paired_secret(
        node_priv,
        claimed["hub_public_key_pem"],
        pairing_id=pairing_id,
        node_id="edge-pi-garage",
        nonce_b64=claimed["nonce_b64"],
        ciphertext_b64=claimed["ciphertext_b64"],
    )
    assert recovered == secret

    # 6. One-time pickup: second claim is rejected (ciphertext wiped)
    with pytest.raises(KeyError):
        mgr.claim_pairing(pairing_id, node_id="edge-pi-garage", signature_b64=valid_sig, now=1040.0)

    # 7. Revocation removes pinned node AND invalidates any unclaimed approval bundle
    req2 = mgr.request_pairing(node_id="edge-pi-garage", public_key_pem=node_pub_pem, now=1045.0)
    mgr.approve_pairing(
        req2["pairing_id"],
        secret_value=secret,
        approved_by="owner",
        expected_fingerprint=req2["node_fingerprint"],
        now=1046.0,
    )
    assert mgr.revoke_node("edge-pi-garage") is True
    assert mgr.list_paired_nodes() == []
    sig2 = sign_claim_proof(node_priv, req2["pairing_id"], "edge-pi-garage")
    with pytest.raises(KeyError):
        mgr.claim_pairing(req2["pairing_id"], node_id="edge-pi-garage", signature_b64=sig2, now=1047.0)

    # 8. Corrupt pin store fails closed rather than silently returning empty
    mgr.store_path.write_text("{corrupt json", encoding="utf-8")
    with pytest.raises(RuntimeError, match="unreadable or corrupt"):
        mgr.list_paired_nodes()


def test_mdns_txt_advertises_hub_fingerprint_and_pairing_flag(tmp_path: Path):
    mgr = NodePairingManager(data_dir=tmp_path / "pairing")
    disc = EcosystemDiscovery(registry_port=8500, host="127.0.0.1", hub_fingerprint=mgr.hub_fingerprint)
    props = disc.build_txt_properties()
    assert props[b"role"] == b"registry"
    assert props[b"pairing"] == b"1"
    assert props[b"pubkey_fp"] == mgr.hub_fingerprint.encode("ascii")


def test_registry_pairing_routes_enforce_step_up_and_freeze(tmp_path: Path, monkeypatch):
    secret = "p" * 64
    monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", secret)
    monkeypatch.setenv("ECOSYSTEM_REGISTRY_FILE", str(tmp_path / "registry.json"))
    monkeypatch.setenv("ECOSYSTEM_CAPABILITIES_FILE", str(tmp_path / "caps.json"))
    monkeypatch.setenv("ECOSYSTEM_NOTIFICATIONS_DB", str(tmp_path / "notify.db"))
    monkeypatch.setenv("ECOSYSTEM_AI_PROFILE_FILE", str(tmp_path / "ai_profile.json"))
    monkeypatch.setenv("ECOSYSTEM_POLICY_KEY_DIR", str(tmp_path / "pkeys"))
    monkeypatch.setenv("ECOSYSTEM_POLICY_STATE_FILE", str(tmp_path / "pstate.json"))
    monkeypatch.setenv("ECOSYSTEM_STEP_UP_FILE", str(tmp_path / "step_up.json"))
    monkeypatch.setenv("ECOSYSTEM_APPROVALS_DB", str(tmp_path / "approvals.db"))
    monkeypatch.setenv("ECOSYSTEM_PAIRING_DIR", str(tmp_path / "pairing"))
    monkeypatch.setenv("ECOSYSTEM_DISABLE_MDNS", "1")

    from registry.app import app

    node_priv, node_pub_pem = generate_ecdsa_keypair()

    with TestClient(app) as client:
        # App lifespan wires EcosystemDiscovery with the same pairing manager fingerprint
        txt = app.state.discovery.build_txt_properties()
        assert txt[b"pairing"] == b"1"
        assert txt[b"pubkey_fp"] == app.state.pairing_manager.hub_fingerprint.encode("ascii")

        # Invalid ttl_seconds returns 400
        r_bad_ttl = client.post(
            "/pairing/request",
            json={"node_id": "bad-ttl", "public_key_pem": node_pub_pem, "ttl_seconds": "not-an-int"},
        )
        assert r_bad_ttl.status_code == 400
        # Enroll TOTP for operator step-up
        r_totp = client.post("/auth/step-up/totp/enroll", json={"operator_id": "admin"})
        assert r_totp.status_code == 200
        totp_secret = r_totp.json()["secret"]

        # Hub identity endpoint exposes fingerprint
        r_id = client.get("/pairing/identity")
        assert r_id.status_code == 200
        assert r_id.json()["hub_fingerprint"].startswith("sha256:")

        # Joining node requests pairing
        r_req = client.post(
            "/pairing/request",
            json={"node_id": "lan-mac-mini", "public_key_pem": node_pub_pem, "roles": ["ai_host"]},
        )
        assert r_req.status_code == 200
        pid = r_req.json()["pairing_id"]
        sas = r_req.json()["sas_code"]
        node_fp = r_req.json()["node_fingerprint"]

        # Freeze blocks pairing approval (HTTP 423)
        assert client.post("/policy/freeze", json={"initiated_by": "owner", "reason": "freeze check"}).status_code == 200
        code1 = compute_totp(totp_secret)
        r_frozen = client.post(
            f"/pairing/{pid}/approve",
            json={"operator_id": "admin", "totp_code": code1, "expected_sas": sas, "expected_fingerprint": node_fp},
        )
        assert r_frozen.status_code == 423

        # Resume with step-up, then approve pairing with step_up_token
        r_ver = client.post("/auth/step-up/totp/verify", json={"operator_id": "admin", "code": code1})
        assert r_ver.status_code == 200
        token = r_ver.json()["step_up_token"]
        assert client.post("/policy/resume", json={"step_up_token": token, "reason": "clear"}).status_code == 200

        r_app = client.post(
            f"/pairing/{pid}/approve",
            json={"step_up_token": token, "expected_sas": sas, "expected_fingerprint": node_fp},
        )
        assert r_app.status_code == 200

        # Claim & decrypt
        sig = sign_claim_proof(node_priv, pid, "lan-mac-mini")
        r_claim = client.post(f"/pairing/{pid}/claim", json={"node_id": "lan-mac-mini", "signature": sig})
        assert r_claim.status_code == 200
        c = r_claim.json()
        assert decrypt_paired_secret(
            node_priv,
            c["hub_public_key_pem"],
            pairing_id=pid,
            node_id="lan-mac-mini",
            nonce_b64=c["nonce_b64"],
            ciphertext_b64=c["ciphertext_b64"],
        ) == secret
