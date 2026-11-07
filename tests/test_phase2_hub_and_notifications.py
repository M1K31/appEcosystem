"""Phase 2 tests: SingleHostLock, CapabilityRegistry, DurableOutbox, NotificationRouter, HubRuntime, and Registry REST routes."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from ecosystem_auth.tokens import sign_request, verify_request
from ecosystem_client.config import EcosystemConfig
from ecosystem_client.contracts import build_notification_envelope
from ecosystem_hub import (
    CapabilityRegistry,
    DurableOutbox,
    HubRole,
    HubRuntime,
    SingleHostLock,
)
from registry.notifications import (
    NotificationRouter,
    is_in_quiet_hours,
    parse_ttl_seconds,
    redact_notification_text,
)

SECRET = "phase2-hub-notify-test-secret-0123456789abcdef"


def _sample_capability(app: str = "openeye", cap: str = "camera.record_clip", device_id: str = "nvr-01") -> dict:
    return {
        "schema_version": 1,
        "capability": cap,
        "version": 1,
        "description": "Record incident clip",
        "provider": {"app": app, "device_id": device_id},
        "action_class": "investigate",
        "required_grant": "camera:record",
        "timeout_seconds": 30,
        "cancellable": True,
        "idempotent": True,
        "offline_behavior": "run_local",
    }


class TestSingleHostLock:
    def test_exclusive_lock_and_owner_metadata(self, tmp_path: Path):
        lock_file = tmp_path / "hub-host.lock"
        first = SingleHostLock(lock_file)
        second = SingleHostLock(lock_file)

        assert first.acquire(app_name="ai_for_survival", hub_url="http://127.0.0.1:8500", priority=100)
        assert first.is_held
        meta = second.inspect_owner()
        assert meta is not None
        assert meta["app_name"] == "ai_for_survival"
        assert meta["priority"] == 100

        # Competing local app must fail non-blocking acquire
        assert not second.acquire(app_name="openeye", hub_url="http://127.0.0.1:8500", priority=50)

        first.release()
        assert not first.is_held
        assert second.acquire(app_name="openeye", hub_url="http://127.0.0.1:8500", priority=50)
        second.release()


class TestCapabilityRegistry:
    def test_register_resolve_withdraw_and_persistence(self, tmp_path: Path):
        store_path = tmp_path / "capabilities.json"
        reg = CapabilityRegistry(store_path)

        # Unregistered capability gives explicit reason
        missing = reg.resolve("scan.request")
        assert not missing.available
        assert "No installed project" in (missing.unavailable_reason or "")

        reg.register(_sample_capability("openeye", "camera.record_clip", "nvr-01"))
        active = reg.resolve("camera.record_clip")
        assert active.available
        assert len(active.providers) == 1

        # Reload from persisted file
        reloaded = CapabilityRegistry(store_path)
        assert reloaded.resolve("camera.record_clip").available

        # Provider withdrawal marks dependent capability unavailable with explicit reason
        reloaded.withdraw_provider("openeye", reason="Provider 'openeye' stopped")
        after = reloaded.resolve("camera.record_clip")
        assert not after.available
        assert "Provider 'openeye' stopped" in (after.unavailable_reason or "")


class TestDurableOutbox:
    @pytest.mark.asyncio
    async def test_offline_dedupe_eviction_and_flush(self, tmp_path: Path):
        outbox = DurableOutbox(tmp_path / "outbox.db", max_items=12)

        n1 = build_notification_envelope(
            "notify.security",
            "aegissiem",
            "high",
            "SSH brute force",
            "5 failures on router",
            dedupe_key="inc-42",
        )
        n1_dup = build_notification_envelope(
            "notify.security",
            "aegissiem",
            "high",
            "SSH brute force duplicate",
            "6 failures on router",
            dedupe_key="inc-42",
        )
        assert outbox.enqueue(n1) is True
        assert outbox.enqueue(n1_dup) is False
        assert outbox.pending_count() == 1

        delivered_ids: list[str] = []

        async def _deliver(env: dict) -> bool:
            delivered_ids.append(env["id"])
            return True

        res = await outbox.flush(_deliver)
        assert res == {"delivered": 1, "failed": 0, "remaining": 0}
        assert delivered_ids == [n1["id"]]


class TestNotificationRouter:
    def test_quiet_hours_and_ttl_helpers(self):
        assert parse_ttl_seconds("30s") == 30
        assert parse_ttl_seconds("15m") == 900
        assert parse_ttl_seconds("24h") == 86400
        assert is_in_quiet_hours("23:00-07:00", datetime(2026, 11, 1, 23, 30))
        assert is_in_quiet_hours("23:00-07:00", datetime(2026, 11, 2, 6, 45))
        assert not is_in_quiet_hours("23:00-07:00", datetime(2026, 11, 2, 12, 0))

        scrubbed = redact_notification_text(
            "Alert in /Users/alice/secrets with token ghp_1234567890abcdefghijklmnop"
        )
        assert "/Users/alice" not in scrubbed
        assert "ghp_" not in scrubbed
        assert "[REDACTED]" in scrubbed

    @pytest.mark.asyncio
    async def test_cross_app_dedupe_quiet_hours_and_federated_push(self, tmp_path: Path):
        pushed: list[tuple[dict, dict]] = []

        async def _fake_push(envelope: dict, sub: dict) -> bool:
            pushed.append((envelope, sub))
            return True

        # Clock pinned inside quiet hours (02:15 AM)
        router = NotificationRouter(
            tmp_path / "notify.db",
            hmac_secret=SECRET,
            channel_handlers={"federated_push": _fake_push},
            clock=lambda: datetime(2026, 11, 2, 2, 15),
        )
        router.upsert_subscription(
            {
                "subscriber_id": "mikel-iphone",
                "device": "iphone-16",
                "channels": ["federated_push"],
                "min_severity": "medium",
                "quiet_hours": "23:00-07:00",
                "bypass_quiet_for": ["critical"],
                "webhook_url": "http://127.0.0.1:8200/api/ecosystem/push",
            }
        )

        # 1. High severity during quiet hours -> deferred, not pushed immediately
        high_alert = build_notification_envelope(
            "notify.security",
            "aegissiem",
            "high",
            "Unusual outbound DNS burst",
            "Observed on /Users/mikel/laptop",
            dedupe_key="incident:dns-burst:01",
        )
        r1 = await router.route(high_alert)
        assert r1["status"] == "routed"
        assert r1["deferred"] == ["mikel-iphone"]
        assert router.deferred_count("mikel-iphone") == 1
        assert len(pushed) == 0

        # 2. Duplicate dedupe_key from cyber-agents -> globally deduplicated!
        dup_from_cyber = build_notification_envelope(
            "notify.security",
            "cyber-agents",
            "high",
            "Correlated DNS burst",
            "Same incident from daemon",
            dedupe_key="incident:dns-burst:01",
        )
        r_dup = await router.route(dup_from_cyber)
        assert r_dup["status"] == "deduplicated"
        assert r_dup["original_id"] == high_alert["id"]

        # 3. Critical severity -> bypasses quiet hours and delivers redacted copy!
        crit_alert = build_notification_envelope(
            "notify.security",
            "openeye",
            "critical",
            "Perimeter intrusion",
            "Clip saved under /Users/mikel/clips/01.mp4",
            dedupe_key="incident:perimeter:99",
        )
        r_crit = await router.route(crit_alert)
        assert r_crit["status"] == "routed"
        assert r_crit["delivered"] == ["mikel-iphone:federated_push"]
        assert len(pushed) == 1
        assert "/Users/mikel" not in pushed[0][0]["body"]

        # 4. local_only notification never leaves host via remote push or remote recent feed
        local_note = build_notification_envelope(
            "notify.system",
            "openeye",
            "critical",
            "Local camera calibration",
            "Internal diagnostics",
            dedupe_key="local:calib:1",
            privacy="local_only",
        )
        await router.route(local_note)
        assert len(pushed) == 1  # unchanged!
        recent_public = router.recent_notifications(include_local_only=False)
        assert all(n["id"] != local_note["id"] for n in recent_public)


class TestRegistryPhase2Endpoints:
    def test_capabilities_and_notifications_rest_lifecycle(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", SECRET)
        monkeypatch.setenv("ECOSYSTEM_REGISTRY_FILE", str(tmp_path / "registry.json"))
        monkeypatch.setenv("ECOSYSTEM_AI_PROFILE_FILE", str(tmp_path / "ai_profile.json"))
        monkeypatch.setenv("ECOSYSTEM_APPS_FILE", str(tmp_path / "apps.json"))
        monkeypatch.setenv("ECOSYSTEM_CAPABILITIES_FILE", str(tmp_path / "capabilities.json"))
        monkeypatch.setenv("ECOSYSTEM_NOTIFICATIONS_DB", str(tmp_path / "notifications.db"))

        from registry.app import app

        with TestClient(app) as client:
            # Register service + capability
            reg_body = {
                "name": "openeye",
                "host": "127.0.0.1",
                "port": 8200,
                "health_endpoint": "/health",
                "priority": 50,
            }
            r_svc = client.post(
                "/register",
                json=reg_body,
                headers=sign_request("POST", "/register", SECRET, body=reg_body),
            )
            assert r_svc.status_code == 201

            cap_body = {"capabilities": [_sample_capability("openeye", "camera.record_clip")]}
            r_cap = client.post(
                "/capabilities/register",
                json=cap_body,
                headers=sign_request("POST", "/capabilities/register", SECRET, body=cap_body),
            )
            assert r_cap.status_code == 201

            resolved = client.get("/capabilities?capability=camera.record_clip&resolve=true").json()
            assert resolved["available"] is True

            # Publish notification twice with same dedupe_key
            note = build_notification_envelope(
                "notify.security",
                "openeye",
                "high",
                "Person at front door",
                "Confidence 0.96",
                dedupe_key="openeye:person:front:1",
                secret=SECRET,
            )
            r_n1 = client.post(
                "/notifications/publish",
                json=note,
                headers=sign_request("POST", "/notifications/publish", SECRET, body=note),
            )
            assert r_n1.status_code == 200
            assert r_n1.json()["status"] == "routed"

            r_n2 = client.post(
                "/notifications/publish",
                json=note,
                headers=sign_request("POST", "/notifications/publish", SECRET, body=note),
            )
            assert r_n2.status_code == 200
            assert r_n2.json()["status"] == "deduplicated"

            recent = client.get("/notifications/recent").json()["notifications"]
            assert len(recent) == 1

            # Deregistering service automatically marks its capabilities unavailable with reason!
            r_del = client.delete(
                "/deregister/openeye",
                headers=sign_request("DELETE", "/deregister/openeye", SECRET),
            )
            assert r_del.status_code == 200
            resolved_after = client.get("/capabilities?capability=camera.record_clip&resolve=true").json()
            assert resolved_after["available"] is False
            assert "deregistered" in (resolved_after["unavailable_reason"] or "")


class TestHubRuntime:
    @pytest.mark.asyncio
    async def test_off_mode_and_tier0_auto_host_guard(self, tmp_path: Path):
        cfg = EcosystemConfig(registry_url="http://127.0.0.1:59999", hmac_secret=SECRET)
        rt = HubRuntime(
            "openeye",
            priority=50,
            role=HubRole.OFF,
            capabilities=[_sample_capability("openeye", "camera.record_clip")],
            config=cfg,
            lock_path=tmp_path / "hub.lock",
            outbox_path=tmp_path / "outbox.db",
        )
        mode = await rt.start()
        assert mode == "standalone"
        assert rt.resolve_capability("camera.record_clip").available

        res = await rt.notify(
            "notify.security",
            "medium",
            "Offline motion",
            "Queued while hub off",
            dedupe_key="offline:1",
        )
        assert res["status"] == "queued_offline"
        assert rt.outbox.pending_count() == 1
        await rt.stop()

        # Verify T0_MINIMAL (<4 GB RAM) declines auto-hosting
        from ecosystem_ai.hardware import HardwareInfo

        minimal_hw = HardwareInfo(
            ram_gb=2.0,
            cpu_cores=4,
            arch="aarch64",
            os_name="Linux",
            has_gpu=False,
            vram_gb=0.0,
            free_disk_gb=8.0,
        )
        rt_minimal = HubRuntime(
            "magicmirror",
            priority=10,
            role="auto",
            config=cfg,
            lock_path=tmp_path / "hub2.lock",
            outbox_path=tmp_path / "outbox2.db",
        )
        with patch("ecosystem_ai.hardware.probe", return_value=minimal_hw):
            assert rt_minimal._can_auto_host() is False
