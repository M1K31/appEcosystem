"""An approval granted in a dashboard executes the stored command, after re-evaluation."""
from __future__ import annotations

import time

import httpx
import pytest
from fastapi.testclient import TestClient

from ecosystem_client.contracts import build_command_envelope
from ecosystem_hub import HubApprovalVerifier
from tests.test_command_dispatch import SECRET
from tests.test_command_routes import Hub, _env

INSPECT = "network.inspect_host"
PARAMS = {"host": "192.168.1.20"}


class ApprovalHub(Hub):
    def add_verified_provider(self, name, capability, action_class, **kw):
        """A provider that confirms approvals with this hub, as a real app does."""
        provider = self.add_provider(name, capability, action_class, **kw)
        self.verifier_calls = getattr(self, "verifier_calls", [])
        inner = HubApprovalVerifier(
            "http://hub.test",
            SECRET,
            app_name=name,
            client_factory=lambda: httpx.AsyncClient(transport=httpx.ASGITransport(app=self.client.app)),
        )

        async def verifier(envelope):
            verdict = await inner(envelope)
            self.verifier_calls.append((envelope["authorization_ref"], verdict))
            return verdict

        provider.receiver._verifier = verifier
        provider.receiver._context_verifier = inner.confirm_context
        return provider

    def step_up(self):
        return self.state.step_up_auth.issue_step_up_token("admin", auth_method="totp")["step_up_token"]

    def approve(self, approval_id):
        return self.client.post(f"/approvals/{approval_id}/approve", json={"step_up_token": self.step_up()})

    def deny(self, approval_id):
        return self.client.post(f"/approvals/{approval_id}/deny", json={"step_up_token": self.step_up()})

    def pending(self, **over):
        doc = self.dispatch(self.body(INSPECT, parameters=dict(PARAMS), **over)).json()
        assert doc["status"] == "pending_approval", doc
        return doc

    def command(self, command_id):
        return self.client.get(f"/commands/{command_id}").json()


@pytest.fixture
def hub(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path)
    from registry.app import app

    with TestClient(app) as client:
        h = ApprovalHub(client, tmp_path)
        h.register_service("ai_for_survival")
        yield h


def test_approve_executes_the_stored_command(hub):
    provider = hub.add_verified_provider("aegissiem", INSPECT, "investigate")
    doc = hub.pending()
    assert provider.envelopes == []

    resp = hub.approve(doc["approval_id"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "approved"
    assert body["command"]["command_id"] == doc["command_id"]
    assert body["command"]["status"] == "completed"
    assert len(provider.calls) == 1
    sent = provider.envelopes[0]
    assert sent["authorization_ref"] == f"approval:{doc['approval_id']}"
    assert sent["id"] == doc["command_id"]
    assert sent["idempotency_key"] == "key-1"
    record = hub.command(doc["command_id"])
    assert record["status"] == "completed"
    events = [e["event"] for e in record["events"]]
    assert "approval_granted" in events and events[-1] == "provider_answered"


def test_provider_confirms_the_approval_with_the_hub(hub):
    hub.add_verified_provider("aegissiem", INSPECT, "investigate")
    doc = hub.pending()
    hub.approve(doc["approval_id"])
    assert hub.verifier_calls == [(f"approval:{doc['approval_id']}", True)]


def test_provider_that_cannot_confirm_the_approval_refuses(hub):
    provider = hub.add_provider("aegissiem", INSPECT, "investigate")  # no verifier configured
    doc = hub.pending()
    body = hub.approve(doc["approval_id"]).json()
    assert body["command"]["status"] == "denied"
    assert body["command"]["error"] == "approval required"
    assert provider.calls == []


def test_approve_while_frozen_executes_nothing(hub):
    provider = hub.add_verified_provider("aegissiem", INSPECT, "investigate")
    doc = hub.pending()
    hub.state.policy_engine.freeze(initiated_by="test")
    resp = hub.approve(doc["approval_id"])
    assert resp.status_code == 403
    assert provider.envelopes == []
    assert hub.command(doc["command_id"])["status"] == "pending_approval"


def test_policy_changed_before_approval_denies(hub):
    provider = hub.add_verified_provider("aegissiem", INSPECT, "investigate")
    doc = hub.pending(actor={"app": "ai_for_survival", "id": "nightly-rule", "type": "automation"})
    hub.state.policy_engine.set_mode("maintenance", operator_id="admin", auth_method="totp")

    body = hub.approve(doc["approval_id"]).json()
    assert body["status"] == "approved"
    assert body["command"]["status"] == "denied"
    assert "Maintenance" in body["command"]["error"]
    assert provider.envelopes == []


def test_the_callers_restrictive_trigger_is_remembered_for_re_evaluation(hub):
    provider = hub.add_verified_provider("aegissiem", INSPECT, "investigate")
    doc = hub.pending(context={"trigger": "schedule"})
    hub.state.policy_engine.set_mode("maintenance", operator_id="admin", auth_method="totp")
    body = hub.approve(doc["approval_id"]).json()
    assert body["command"]["status"] == "denied"
    assert provider.envelopes == []


def test_provider_gone_at_approval_time(hub):
    hub.add_verified_provider("aegissiem", INSPECT, "investigate")
    doc = hub.pending()
    hub.state.registry.deregister("aegissiem")
    body = hub.approve(doc["approval_id"]).json()
    assert body["status"] == "approved"
    assert body["command"]["status"] == "provider_unavailable"


def test_second_approve_does_not_execute_again(hub):
    provider = hub.add_verified_provider("aegissiem", INSPECT, "investigate")
    doc = hub.pending()
    assert hub.approve(doc["approval_id"]).status_code == 200
    assert hub.approve(doc["approval_id"]).status_code == 409
    assert len(provider.calls) == 1


def test_deny_marks_command_denied(hub):
    provider = hub.add_verified_provider("aegissiem", INSPECT, "investigate")
    doc = hub.pending()
    resp = hub.deny(doc["approval_id"])
    assert resp.status_code == 200
    record = hub.command(doc["command_id"])
    assert record["status"] == "denied"
    assert record["error"] == "approval denied"
    assert provider.envelopes == []
    # A denied approval cannot be turned into an execution afterwards.
    assert hub.approve(doc["approval_id"]).status_code == 409
    assert provider.envelopes == []


def test_expiry_marks_command_denied(hub):
    provider = hub.add_verified_provider("aegissiem", INSPECT, "investigate")
    doc = hub.pending()
    expired = hub.state.approval_service.expire_due(now=time.time() + 10**7)
    assert [r["approval_id"] for r in expired] == [doc["approval_id"]]
    record = hub.command(doc["command_id"])
    assert record["status"] == "denied"
    assert record["error"] == "approval expired"
    assert provider.envelopes == []


def test_approving_an_expired_request_executes_nothing(hub, monkeypatch):
    provider = hub.add_verified_provider("aegissiem", INSPECT, "investigate")
    doc = hub.pending()
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + 10**7)
    resp = hub.approve(doc["approval_id"])
    monkeypatch.setattr(time, "time", real_time)
    assert resp.status_code == 409
    assert provider.envelopes == []
    record = hub.command(doc["command_id"])
    assert (record["status"], record["error"]) == ("denied", "approval expired")


def test_provisional_containment_approved_keeps_its_result(hub):
    provider = hub.add_verified_provider("aegissiem", "containment.block_ip", "contain")
    doc = hub.dispatch(
        hub.body("containment.block_ip", target={"scope": "local", "identifier": "203.0.113.9"}, parameters={})
    ).json()
    assert doc["status"] == "completed" and doc["approval_id"]
    body = hub.approve(doc["approval_id"]).json()
    assert body["command"]["status"] == "completed"
    assert len(provider.calls) == 1
    assert hub.command(doc["command_id"])["events"][-1]["event"] == "approval_granted"


def test_denied_provisional_containment_records_revert_requested(hub):
    provider = hub.add_verified_provider("aegissiem", "containment.block_ip", "contain")
    doc = hub.dispatch(
        hub.body("containment.block_ip", target={"scope": "local", "identifier": "203.0.113.9"}, parameters={})
    ).json()
    assert hub.deny(doc["approval_id"]).status_code == 200
    record = hub.command(doc["command_id"])
    assert record["status"] == "completed"  # it did run; the record says a revert was asked for
    assert record["events"][-1]["event"] == "revert_requested"
    assert record["events"][-1]["detail"]["outcome"] == "denied"
    assert len(provider.calls) == 1


def test_plain_approval_without_command_is_unchanged(hub):
    created = hub.client.post("/approvals", json={"action": "manual_review", "action_class": "investigate"})
    assert created.status_code == 201
    body = hub.approve(created.json()["approval_id"]).json()
    assert body["status"] == "approved"
    assert "command" not in body


@pytest.mark.asyncio
async def test_forged_approval_reference_is_refused_by_provider(hub):
    provider = hub.add_verified_provider("aegissiem", INSPECT, "investigate")
    actor = {"id": "x", "type": "service", "app": "ai_for_survival", "device_id": "local-device"}
    # Any first-party app holds the shared secret and can sign this. The hub has no such command.
    forged = build_command_envelope(
        INSPECT, "investigate", actor, {"scope": "local", "identifier": "192.168.1.20"}, SECRET,
        parameters=dict(PARAMS), idempotency_key="forged-1", authorization_ref="approval:01HFORGEDAPPROVAL",
    )
    status, body = await provider.receiver.handle(forged)
    assert (status, body["status"]) == (200, "denied")
    assert provider.calls == []


def test_a_used_approval_cannot_be_replayed_to_the_provider(hub):
    provider = hub.add_verified_provider("aegissiem", INSPECT, "investigate")
    doc = hub.pending()
    hub.approve(doc["approval_id"])
    assert len(provider.calls) == 1
    actor = provider.envelopes[0]["actor"]
    # Same command id and approval, new idempotency key: an attempt to run it a second time.
    replay = build_command_envelope(
        INSPECT, "investigate", actor, {"scope": "local", "identifier": "192.168.1.20"}, SECRET,
        parameters=dict(PARAMS), idempotency_key="replay-1",
        authorization_ref=f"approval:{doc['approval_id']}", command_id=doc["command_id"],
    )
    with TestClient(provider.app) as direct:
        answer = direct.post("/ecosystem/commands", json=replay)
    assert answer.status_code == 409 or answer.json()["status"] == "denied"
    assert len(provider.calls) == 1


def test_retry_after_unknown_outcome_of_an_approved_command(hub):
    provider = hub.add_verified_provider("aegissiem", INSPECT, "investigate")
    doc = hub.pending()

    class LoseTheAnswer(httpx.AsyncBaseTransport):
        def __init__(self, inner):
            self.inner = inner

        async def handle_async_request(self, request):
            await self.inner.handle_async_request(request)
            raise httpx.ReadTimeout("simulated", request=request)

    normal = hub.state.command_dispatcher._client_factory
    hub.state.command_dispatcher._client_factory = lambda: httpx.AsyncClient(
        mounts={"all://aegissiem.test": LoseTheAnswer(httpx.ASGITransport(app=provider.app))}
    )
    body = hub.approve(doc["approval_id"]).json()
    assert (body["command"]["status"], body["command"]["outcome_unknown"]) == ("failed", True)
    assert len(provider.calls) == 1

    hub.state.command_dispatcher._client_factory = normal
    again = hub.dispatch(hub.body(INSPECT, parameters=dict(PARAMS))).json()
    assert again["command_id"] == doc["command_id"]
    assert again["status"] == "completed"
    assert len(provider.calls) == 1


# ---- final review: an approval that expires anywhere closes its command ----------


def test_listing_approvals_after_expiry_closes_the_command(hub, monkeypatch):
    provider = hub.add_verified_provider("aegissiem", INSPECT, "investigate")
    doc = hub.pending()
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + 10**7)
    assert hub.client.get("/approvals", params={"status": "pending"}).status_code == 200
    monkeypatch.setattr(time, "time", real_time)
    record = hub.command(doc["command_id"])
    assert (record["status"], record["error"]) == ("denied", "approval expired")
    assert provider.envelopes == []


def test_startup_closes_commands_whose_approval_closed_while_unobserved(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path)
    from registry.app import app

    with TestClient(app) as client:
        h = ApprovalHub(client, tmp_path)
        h.register_service("ai_for_survival")
        h.add_verified_provider("aegissiem", INSPECT, "investigate")
        doc = h.pending()
        # Expired behind the listener's back (as an older hub version would have done).
        h.state.approval_service.queue.expire_due(now=time.time() + 10**7)
        assert h.command(doc["command_id"])["status"] == "pending_approval"

    with TestClient(app) as client:
        record = client.get(f"/commands/{doc['command_id']}").json()
        assert (record["status"], record["error"]) == ("denied", "approval expired")


# ---- incident and profile claims are confirmed with the real hub ---------------


def _spy(engine):
    seen = []
    real = engine.decide
    engine.decide = lambda req, **kw: (seen.append(req), real(req, **kw))[1]
    return seen


def test_incident_context_is_confirmed_with_the_hub(hub):
    provider = hub.add_verified_provider("aegissiem", "threat_intel.lookup_ioc", "observe")
    seen = _spy(provider.engine)
    doc = hub.dispatch(hub.body(context={"incident_id": "INC-7", "profile": "full"})).json()
    assert doc["status"] == "completed"
    assert (seen[0].context["incident_id"], seen[0].context["profile"]) == ("INC-7", "full")
    assert hub.command(doc["command_id"])["policy_context"]["incident_id"] == "INC-7"


@pytest.mark.asyncio
async def test_forged_incident_claim_sent_directly_is_dropped(hub):
    provider = hub.add_verified_provider("aegissiem", "threat_intel.lookup_ioc", "observe")
    seen = _spy(provider.engine)
    actor = {"id": "x", "type": "service", "app": "ai_for_survival", "device_id": "local-device"}
    # Signed with the shared secret, sent straight to the provider: the hub never saw it.
    forged = build_command_envelope(
        "threat_intel.lookup_ioc", "observe", actor, {"scope": "local", "identifier": "192.168.1.20"}, SECRET,
        parameters={"indicator": "192.168.1.20", "_policy": {"trigger": "service", "incident_id": "INC-7"}},
        idempotency_key="forged-ctx",
    )
    status, body = await provider.receiver.handle(forged)
    assert status == 200
    assert "incident_id" not in seen[0].context
