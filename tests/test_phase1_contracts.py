"""Phase 1 contract, ULID, JSON Schema, backward-compatibility, and Python<->JS parity tests."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from ecosystem_auth.tokens import sign_payload
from ecosystem_client.config import EcosystemConfig
from ecosystem_client.contracts import (
    EventType,
    SchemaValidationError,
    assert_valid_schema,
    build_command_envelope,
    build_event_envelope_v2,
    build_notification_envelope,
    list_schemas,
    load_schema,
    validate_against_schema,
    verify_command_envelope,
    verify_event_envelope,
)
from ecosystem_client.discovery import DiscoveryMode
from ecosystem_client.event_publisher import EventPublisher
from ecosystem_client.event_subscriber import EventSubscriber
from ecosystem_client.ulid import generate_ulid, is_ulid, ulid_timestamp_ms
from events.schemas import CommandEnvelope, EventEnvelope

REPO_ROOT = Path(__file__).resolve().parent.parent
SECRET = "phase1-contract-test-secret-0123456789abcdef"


class TestUlid:
    def test_format_and_timestamp_roundtrip(self):
        ts_ms = 1_762_000_123_456
        u = generate_ulid(ts_ms)
        assert len(u) == 26
        assert is_ulid(u)
        assert ulid_timestamp_ms(u) == ts_ms

    def test_monotonic_within_same_millisecond(self):
        ids = [generate_ulid() for _ in range(64)]
        assert all(is_ulid(x) for x in ids)
        assert ids == sorted(ids)
        assert len(set(ids)) == 64

    def test_rejects_invalid_ulids(self):
        assert not is_ulid("")
        assert not is_ulid("not-a-ulid")
        assert not is_ulid("8ZZZZZZZZZZZZZZZZZZZZZZZZZ")  # overflows 48-bit timestamp
        with pytest.raises(ValueError):
            ulid_timestamp_ms("invalid")


class TestSchemaParityAndValidation:
    EXPECTED_SCHEMAS = [
        "capability-manifest.v1",
        "command-envelope.v1",
        "event-envelope.v2",
        "notification-envelope.v1",
        "policy-state.v1",
    ]

    def test_all_five_schemas_present_and_mirrored_identically(self):
        assert list_schemas() == self.EXPECTED_SCHEMAS
        canonical_dir = REPO_ROOT / "contracts" / "schemas"
        py_dir = REPO_ROOT / "ecosystem_client" / "schemas"
        js_dir = REPO_ROOT / "ecosystem_client_js" / "schemas"

        for name in self.EXPECTED_SCHEMAS:
            fname = f"{name}.schema.json"
            c_bytes = (canonical_dir / fname).read_bytes()
            assert (py_dir / fname).read_bytes() == c_bytes, f"Python mirror drift on {fname}"
            assert (js_dir / fname).read_bytes() == c_bytes, f"JS mirror drift on {fname}"
            parsed = load_schema(name)
            assert parsed["$schema"] == "https://json-schema.org/draft/2020-12/schema"

    def test_expanded_event_types(self):
        required_types = {
            "scan.requested",
            "scan.completed",
            "scan.finding",
            "policy.decision",
            "policy.restrictions_changed",
            "ecosystem.freeze_requested",
            "ecosystem.freeze_applied",
            "approval.requested",
            "approval.decided",
            "capability.registered",
            "notify.security",
            "notify.approval",
            "compute.job.started",
            "model.published",
            "device.enrolled",
        }
        actual_values = {member.value for member in EventType}
        assert required_types.issubset(actual_values)
        assert len(actual_values) >= 55

    def test_capability_manifest_and_policy_state_schemas(self):
        manifest = {
            "schema_version": 1,
            "capability": "camera.record_clip",
            "version": 1,
            "description": "Capture a short encrypted incident video clip on an OpenEye node.",
            "provider": {"app": "openeye", "device_id": "nvr-01"},
            "action_class": "investigate",
            "required_grant": "camera:record",
            "requirements": {"os": ["linux", "darwin", "win32"], "min_tier": 1, "needs_gpu": False},
            "side_effects": ["writes_encrypted_clip"],
            "timeout_seconds": 30,
            "cancellable": True,
            "idempotent": True,
            "offline_behavior": "run_local",
        }
        assert_valid_schema(manifest, "capability-manifest.v1")

        bad_manifest = dict(manifest, offline_behavior="do_whatever")
        assert validate_against_schema(bad_manifest, "capability-manifest.v1")

        policy_state = {
            "schema_version": 1,
            "policy_version": 4,
            "mode": "normal",
            "restrictions": "on",
            "frozen": False,
            "freeze_info": None,
            "active_override": None,
            "always_enforced": ["command_authentication", "freeze", "audit"],
            "authority": "hub_synced",
            "updated_at": "2026-11-01T18:00:00Z",
        }
        assert_valid_schema(policy_state, "policy-state.v1")


class TestEventV2AndLegacyV1Compatibility:
    @pytest.mark.asyncio
    async def test_v2_publisher_validates_schema_and_dispatches(self):
        cfg = EcosystemConfig(hmac_secret=SECRET)
        pub = EventPublisher(cfg, mode=DiscoveryMode.STANDALONE, service_name="openeye")
        env = pub._build_envelope(
            EventType.SECURITY_PERSON_DETECTED.value,
            {"camera": "driveway", "confidence": 0.94},
            correlation_id="corr-001",
        )
        assert_valid_schema(env, "event-envelope.v2")
        assert verify_event_envelope(env, SECRET)

        received = []
        sub = EventSubscriber(hmac_secret=SECRET)
        sub.on("security.*", lambda payload: _async_append(received, payload))
        await sub.dispatch(env)
        assert len(received) == 1
        assert received[0]["source"]["app"] == "openeye"
        assert received[0]["source"]["device_id"]

    @pytest.mark.asyncio
    async def test_legacy_v1_wire_envelope_still_verifies_in_subscriber_and_pydantic(self):
        legacy_signable = {
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "type": "security.alert",
            "source": "aegissiem",
            "timestamp": 1700000000.5,
            "data": {"ip": "192.0.2.99"},
        }
        legacy_wire = dict(
            legacy_signable,
            signature=sign_payload(legacy_signable, SECRET),
        )
        assert verify_event_envelope(legacy_wire, SECRET)

        parsed = EventEnvelope(**legacy_wire)
        assert parsed.source == "aegissiem"
        assert sign_payload(parsed.signable_dict(), SECRET) == legacy_wire["signature"]

        received = []
        sub = EventSubscriber(hmac_secret=SECRET)
        sub.on("security.alert", lambda payload: _async_append(received, payload))
        await sub.dispatch(legacy_wire)
        assert len(received) == 1


class TestCommandAndNotificationEnvelopes:
    def test_command_envelope_signing_expiry_and_notify_rejection(self):
        actor = {
            "id": "op-mikel",
            "type": "operator",
            "app": "appecosystem-hub",
            "device_id": "macbook-pro",
            "auth_method": "totp",
        }
        target = {
            "scope": "device",
            "device_id": "edge-nvr",
            "service": "openeye",
        }
        cmd = build_command_envelope(
            command="scan.run_baseline",
            action_class="investigate",
            actor=actor,
            target=target,
            secret=SECRET,
            parameters={"profile": "quick"},
            ttl_seconds=30,
            issued_at=1700000000,
            authorization_ref="approval:01J9ABCDEF0123456789ABCDEF",
            rationale="Routine baseline audit",
        )
        ok, reason = verify_command_envelope(cmd, SECRET, now=1700000015)
        assert ok and reason == "ok"

        # Expired command rejected
        ok_exp, reason_exp = verify_command_envelope(cmd, SECRET, now=1700000031)
        assert not ok_exp and "expired" in reason_exp

        # Tampered parameter rejected
        tampered = json.loads(json.dumps(cmd))
        tampered["parameters"]["profile"] = "aggressive"
        ok_tamp, reason_tamp = verify_command_envelope(tampered, SECRET, now=1700000015)
        assert not ok_tamp and "signature" in reason_tamp

        # Notification reference NEVER authorizes a command
        with pytest.raises(ValueError):
            build_command_envelope(
                command="containment.isolate_host",
                action_class="contain",
                actor=actor,
                target=target,
                secret=SECRET,
                authorization_ref="notify:01J9ABCDEF0123456789ABCDEF",
            )
        with pytest.raises(ValueError):
            CommandEnvelope(
                command="containment.isolate_host",
                action_class="contain",
                actor=actor,
                target=target,
                authorization_ref="notify.security",
            )

    def test_notification_envelope_schema(self):
        note = build_notification_envelope(
            notify_type="notify.security",
            source_app="aegissiem",
            severity="high",
            title="Repeated SSH authentication failures",
            body="5 failed attempts on gateway-01 within 60s.",
            dedupe_key="aegissiem:ssh-bruteforce:gateway-01:2026110118",
            actions=[
                {"id": "open_incident", "label": "Inspect", "requires": "none"},
                {"id": "freeze_ecosystem", "label": "Freeze", "requires": "freeze_grant"},
            ],
            secret=SECRET,
        )
        assert_valid_schema(note, "notification-envelope.v1")
        assert note["privacy"] == "redacted"
        assert len(note["signature"]) == 64


@pytest.mark.skipif(shutil.which("node") is None, reason="node runtime required")
class TestPythonJavaScriptCrossLanguageParity:
    def test_bidirectional_hmac_and_event_type_parity(self):
        # Integer AND fractional timestamps must verify identically across Python <-> JS
        py_event_int = build_event_envelope_v2(
            "scan.completed",
            "zero-breach-toolkit",
            {"findings": 0, "status": "clean"},
            SECRET,
            device_id=" workstation-1 ",
            timestamp=1700000000,
        )
        py_event_frac = build_event_envelope_v2(
            "notify.security",
            "openeye",
            {"camera": "porch"},
            SECRET,
            device_id="nvr-1",
            correlation_id="corr-xyz",
            timestamp=1700000000.125,
        )
        py_cmd = build_command_envelope(
            command="freeze.request",
            action_class="contain",
            actor={"id": "wall-hud", "type": "operator", "app": "magicmirror", "device_id": "hallway-pi"},
            target={"scope": "ecosystem"},
            secret=SECRET,
            issued_at=1700000000,
            ttl_seconds=60,
        )

        js_script = """
        const contracts = require("./ecosystem_client_js/src/contracts");
        const input = JSON.parse(process.argv[1]);
        const secret = input.secret;

        if (!contracts.verifyEventEnvelope(input.py_event_int, secret)) {
          throw new Error("JS failed to verify py_event_int");
        }
        if (!contracts.verifyEventEnvelope(input.py_event_frac, secret)) {
          throw new Error("JS failed to verify py_event_frac");
        }
        const cmdCheck = contracts.verifyCommandEnvelope(input.py_cmd, secret, { now: 1700000010 });
        if (!cmdCheck.valid) {
          throw new Error("JS failed to verify py_cmd: " + cmdCheck.reason);
        }

        const jsEventInt = contracts.buildEventEnvelopeV2(
          "policy.mode_changed",
          "magicmirror",
          { mode: "incident" },
          secret,
          { deviceId: "pi-4", timestamp: 1700000000 }
        );
        const jsEventFrac = contracts.buildEventEnvelopeV2(
          "ai.recommendation",
          "ai-for-survival",
          { score: 0.88 },
          secret,
          { deviceId: "hub-box", correlationId: "c-42", timestamp: 1700000000.375 }
        );
        const jsCmd = contracts.buildCommandEnvelope(
          "scan.run_quick",
          "investigate",
          { id: "op-1", type: "operator", app: "openeye", device_id: "nvr-1" },
          { scope: "local", device_id: "nvr-1" },
          secret,
          { issuedAt: 1700000000, ttlSeconds: 45 }
        );

        process.stdout.write(JSON.stringify({
          eventTypes: contracts.EventType,
          jsEventInt,
          jsEventFrac,
          jsCmd,
        }));
        """
        payload = json.dumps(
            {
                "secret": SECRET,
                "py_event_int": py_event_int,
                "py_event_frac": py_event_frac,
                "py_cmd": py_cmd,
            }
        )
        proc = subprocess.run(
            ["node", "-e", js_script, payload],
            cwd=str(REPO_ROOT),
            check=True,
            capture_output=True,
            text=True,
        )
        out = json.loads(proc.stdout)

        # Exact EventType dictionary parity
        py_event_types = {member.name: member.value for member in EventType}
        assert out["eventTypes"] == py_event_types

        # Verify JS-signed envelopes in Python (both direct & via Pydantic EventEnvelope)
        assert verify_event_envelope(out["jsEventInt"], SECRET)
        assert verify_event_envelope(out["jsEventFrac"], SECRET)

        parsed_int = EventEnvelope(**out["jsEventInt"])
        assert sign_payload(parsed_int.signable_dict(), SECRET) == out["jsEventInt"]["signature"]

        ok_cmd, reason = verify_command_envelope(out["jsCmd"], SECRET, now=1700000010)
        assert ok_cmd, reason


async def _async_append(target: list, item: object) -> None:
    target.append(item)
