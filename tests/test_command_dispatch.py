"""Hub command dispatcher: provider resolution, first policy gate, forwarding, recording."""
from __future__ import annotations

import asyncio

import httpx
import pytest
from fastapi import FastAPI

from ecosystem_hub import CapabilityRegistry, CommandReceiver, CommandStore, build_command_router
from ecosystem_policy import PolicyEngine
from registry.commands import CommandDispatcher
from registry.models import HealthStatus, ServiceRegistration
from registry.registry import ServiceRegistry

SECRET = "dispatch-test-secret-0123456789abcdef"
ACTOR = {"id": "blue-team", "type": "service", "app": "ai_for_survival", "device_id": "local-device"}
LOCAL = {"scope": "local", "identifier": "192.168.1.20"}


def manifest(capability, app, action_class="observe", **extra):
    doc = {
        "schema_version": 1,
        "capability": capability,
        "version": 1,
        "provider": {"app": app, "device_id": "local-device"},
        "action_class": action_class,
        "required_grant": "none",
        "idempotent": True,
        "cancellable": False,
        "timeout_seconds": 5,
        "offline_behavior": "unavailable",
    }
    doc.update(extra)
    return doc


class Provider:
    """A fake app: a real CommandReceiver behind a real router, with its own policy engine."""

    def __init__(self, name, tmp_path):
        self.name = name
        self.engine = PolicyEngine(authority="hub_synced")
        self.calls: list = []
        self.envelopes: list = []
        self.receiver = CommandReceiver(
            name, secret=SECRET, policy_engine=self.engine, replay_db_path=tmp_path / f"{name}-replay.db"
        )
        self.app = FastAPI()

        @self.app.middleware("http")
        async def _record(request, call_next):
            if request.method == "POST":
                import json

                self.envelopes.append(json.loads(await request.body()))
            return await call_next(request)

        self.app.include_router(build_command_router(self.receiver))

    def offer(self, capability, action_class="observe"):
        async def handler(ctx):
            self.calls.append(ctx)
            return {"handled_by": self.name, "subject": ctx.target.get("identifier")}

        self.receiver.register(capability, action_class, handler)


class FakeApprovals:
    def __init__(self):
        self.requests: list = []

    async def create_request(self, payload):
        self.requests.append(payload)
        return {"approval_id": f"APPROVAL{len(self.requests)}", "status": "pending", **payload}


class FakeNotifications:
    def __init__(self, fail=False):
        self.routed: list = []
        self.fail = fail

    async def route(self, envelope):
        if self.fail:
            raise RuntimeError("sink down")
        self.routed.append(envelope)
        return {"delivered": True}


class FakeAppStore:
    def __init__(self, names):
        self._names = set(names)

    def all_owned_names(self):
        return set(self._names)


class Failing(httpx.AsyncBaseTransport):
    def __init__(self, exc_type=None, status=None):
        self.exc_type, self.status, self.requests = exc_type, status, 0

    async def handle_async_request(self, request):
        self.requests += 1
        if self.exc_type is not None:
            raise self.exc_type("simulated", request=request)
        return httpx.Response(self.status, json={"detail": "boom"})


class World:
    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.store = CommandStore(tmp_path / "commands.db")
        self.caps = CapabilityRegistry(tmp_path / "caps.json")
        self.services = ServiceRegistry()
        self.engine = PolicyEngine(authority="hub_synced")
        self.approvals = FakeApprovals()
        self.notifications = FakeNotifications()
        self.providers: dict[str, Provider] = {}
        self.overrides: dict[str, httpx.AsyncBaseTransport] = {}
        self.app_store = FakeAppStore([])
        self.dispatcher = self.make_dispatcher()

    def make_dispatcher(self, **kw):
        return CommandDispatcher(
            store=self.store,
            capability_registry=self.caps,
            service_registry=self.services,
            policy_engine=self.engine,
            approval_service=self.approvals,
            notification_router=kw.get("notification_router", self.notifications),
            app_store=self.app_store,
            secret_fn=lambda: SECRET,
            client_factory=self._client,
        )

    def _client(self):
        mounts = {}
        for name, provider in self.providers.items():
            mounts[f"all://{name}.test"] = self.overrides.get(name) or httpx.ASGITransport(app=provider.app)
        return httpx.AsyncClient(mounts=mounts)

    def add_provider(self, name, capability, action_class="observe", *, priority=0, port=8089):
        provider = self.providers.get(name) or Provider(name, self.tmp_path)
        self.providers[name] = provider
        provider.offer(capability, action_class)
        self.caps.register(manifest(capability, name, action_class))
        self.services.register(ServiceRegistration(name=name, host=f"{name}.test", port=port, priority=priority))
        return provider

    async def dispatch(self, capability, *, target=None, parameters=None, key="key-1", actor=None, **kw):
        return await self.dispatcher.dispatch(
            requester_app="ai_for_survival",
            identity="shared_secret",
            capability=capability,
            target=target or dict(LOCAL),
            parameters=parameters if parameters is not None else {"indicator": "192.168.1.20"},
            actor=actor or dict(ACTOR),
            rationale=kw.pop("rationale", "test"),
            idempotency_key=key,
            **kw,
        )


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


@pytest.mark.asyncio
async def test_observe_capability_completes_end_to_end(w):
    provider = w.add_provider("aegissiem", "threat_intel.lookup_ioc")
    out = await w.dispatch("threat_intel.lookup_ioc")
    assert out["status"] == "completed"
    assert out["provider"] == "aegissiem"
    assert out["result"] == {"handled_by": "aegissiem", "subject": "192.168.1.20"}
    assert out["decision"]["result"] == "allow"
    assert out["capability"] == "threat_intel.lookup_ioc"
    assert len(provider.calls) == 1
    record = w.store.get(out["command_id"])
    events = [e["event"] for e in record["events"]]
    assert events[0] == "created" and "decided" in events and events[-1] == "provider_answered"
    assert record["events"][0]["detail"]["identity"] == "shared_secret"
    sent = provider.envelopes[0]
    assert sent["id"] == out["command_id"]
    assert sent["idempotency_key"] == "key-1"
    assert sent["actor"]["app"] == "ai_for_survival"


@pytest.mark.asyncio
async def test_unknown_capability_is_provider_unavailable(w):
    provider = w.add_provider("aegissiem", "threat_intel.lookup_ioc")
    out = await w.dispatch("camera.snapshot")
    assert out["status"] == "provider_unavailable"
    assert "camera.snapshot" in out["error"]
    assert provider.calls == [] and provider.envelopes == []


@pytest.mark.asyncio
async def test_unhealthy_provider_is_provider_unavailable(w):
    provider = w.add_provider("aegissiem", "threat_intel.lookup_ioc")
    w.services.get("aegissiem").status = HealthStatus.UNHEALTHY
    out = await w.dispatch("threat_intel.lookup_ioc")
    assert out["status"] == "provider_unavailable"
    assert provider.envelopes == []


@pytest.mark.asyncio
async def test_provider_without_a_service_record_is_provider_unavailable(w):
    w.caps.register(manifest("camera.snapshot", "openeye"))
    out = await w.dispatch("camera.snapshot")
    assert out["status"] == "provider_unavailable"


@pytest.mark.asyncio
async def test_third_party_provider_is_provider_unavailable(w):
    provider = w.add_provider("partner_app", "partner.report")
    w.app_store._names.add("partner_app")
    out = await w.dispatch("partner.report")
    assert out["status"] == "provider_unavailable"
    assert "cannot verify" in out["error"]
    assert provider.envelopes == []


@pytest.mark.asyncio
async def test_named_service_is_used_or_nothing(w):
    aegis = w.add_provider("aegissiem", "threat_intel.lookup_ioc", priority=10)
    harness = w.add_provider("cyber_harness", "threat_intel.lookup_ioc", priority=0, port=8088)
    w.add_provider("openeye", "camera.snapshot", port=8200)

    out = await w.dispatch("threat_intel.lookup_ioc", target={"scope": "local", "service": "cyber_harness"})
    assert (out["status"], out["provider"]) == ("completed", "cyber_harness")
    assert len(harness.calls) == 1 and aegis.calls == []

    # openeye is healthy and registered, but does not offer this capability.
    out2 = await w.dispatch("threat_intel.lookup_ioc", target={"scope": "local", "service": "openeye"}, key="key-2")
    assert out2["status"] == "provider_unavailable"
    assert aegis.calls == [] and len(harness.calls) == 1


@pytest.mark.asyncio
async def test_higher_priority_provider_wins(w):
    low = w.add_provider("cyber_harness", "threat_intel.lookup_ioc", priority=0, port=8088)
    high = w.add_provider("aegissiem", "threat_intel.lookup_ioc", priority=10)
    out = await w.dispatch("threat_intel.lookup_ioc")
    assert out["provider"] == "aegissiem"
    assert len(high.calls) == 1 and low.calls == []


@pytest.mark.asyncio
async def test_gate1_deny_sends_nothing(w):
    provider = w.add_provider("aegissiem", "containment.block_ip", "contain")
    w.engine.freeze(initiated_by="test")
    out = await w.dispatch("containment.block_ip")
    assert out["status"] == "denied"
    assert out["decision"]["frozen"] is True
    assert provider.envelopes == []
    assert w.approvals.requests == []


@pytest.mark.asyncio
async def test_action_class_comes_from_manifest(w):
    provider = w.add_provider("aegissiem", "host.wipe", "remediate")
    out = await w.dispatch("host.wipe", target={"scope": "device", "device_id": "mbp-01"})
    # remediate needs approval by default; nothing the caller sends can relabel it.
    assert out["status"] == "pending_approval"
    assert w.store.get(out["command_id"])["action_class"] == "remediate"
    assert provider.envelopes == []


@pytest.mark.asyncio
async def test_require_approval_stores_and_does_not_forward(w):
    provider = w.add_provider("aegissiem", "network.inspect_host", "investigate")
    out = await w.dispatch("network.inspect_host", rationale="unusual traffic from the printer")
    assert out["status"] == "pending_approval"
    assert out["approval_id"] == "APPROVAL1"
    assert provider.envelopes == []
    req = w.approvals.requests[0]
    assert req["action"] == "network.inspect_host"
    assert req["action_class"] == "investigate"
    assert req["requester_service"] == "ai_for_survival"
    assert req["summary"] == "unusual traffic from the printer"
    assert req["target"]["command_id"] == out["command_id"]
    assert req["target"]["digest"] == w.store.get(out["command_id"])["digest"]
    assert req["async_containment"] is False


@pytest.mark.asyncio
async def test_provisional_containment_forwards_and_opens_approval(w):
    provider = w.add_provider("aegissiem", "containment.block_ip", "contain")
    out = await w.dispatch("containment.block_ip", target={"scope": "local", "identifier": "203.0.113.9"})
    assert out["status"] == "completed"
    assert out["approval_id"] == "APPROVAL1"
    assert len(provider.calls) == 1
    req = w.approvals.requests[0]
    assert req["async_containment"] is True
    assert req["on_deny"] == "revert"
    assert req["revert_plan"]["action"] == "revert_containment.block_ip"
    assert provider.envelopes[0]["authorization_ref"] == "approval:APPROVAL1"
    # The approval request already notifies; no second notification for the same action.
    assert w.notifications.routed == []


@pytest.mark.asyncio
async def test_gate2_can_deny_after_gate1_allowed(w):
    provider = w.add_provider("aegissiem", "threat_intel.lookup_ioc", "investigate")
    # Hub policy: a passive lookup of an external indicator is allowed with a notice.
    # The provider is frozen and refuses.
    provider.engine.freeze(initiated_by="test")
    out = await w.dispatch("threat_intel.lookup_ioc", target={"scope": "external", "identifier": "8.8.8.8"})
    assert out["decision"]["result"] == "allow_and_notify"
    assert out["status"] == "denied"
    assert provider.calls == []
    assert len(provider.envelopes) == 1


@pytest.mark.asyncio
async def test_duplicate_key_does_not_execute_twice(w):
    provider = w.add_provider("aegissiem", "threat_intel.lookup_ioc")
    first = await w.dispatch("threat_intel.lookup_ioc")
    second = await w.dispatch("threat_intel.lookup_ioc")
    assert second["command_id"] == first["command_id"]
    assert second["result"] == first["result"]
    assert len(provider.calls) == 1 and len(provider.envelopes) == 1


@pytest.mark.asyncio
async def test_same_key_different_request_raises_conflict(w):
    from ecosystem_hub import IdempotencyConflict

    w.add_provider("aegissiem", "threat_intel.lookup_ioc")
    await w.dispatch("threat_intel.lookup_ioc")
    with pytest.raises(IdempotencyConflict):
        await w.dispatch("threat_intel.lookup_ioc", parameters={"indicator": "192.168.1.99"})


@pytest.mark.asyncio
async def test_connect_failure_is_provider_unavailable(w):
    w.add_provider("aegissiem", "threat_intel.lookup_ioc")
    w.overrides["aegissiem"] = Failing(httpx.ConnectError)
    out = await w.dispatch("threat_intel.lookup_ioc")
    assert out["status"] == "provider_unavailable"
    assert out["outcome_unknown"] is False


@pytest.mark.asyncio
async def test_timeout_after_send_is_outcome_unknown(w):
    w.add_provider("aegissiem", "threat_intel.lookup_ioc")
    w.overrides["aegissiem"] = Failing(httpx.ReadTimeout)
    out = await w.dispatch("threat_intel.lookup_ioc")
    assert out["status"] == "failed"
    assert out["outcome_unknown"] is True


@pytest.mark.asyncio
async def test_retry_after_unknown_outcome_reuses_provider_result(w):
    provider = w.add_provider("aegissiem", "threat_intel.lookup_ioc")

    class LoseTheAnswer(httpx.AsyncBaseTransport):
        """The provider runs the command, but the hub never sees the response."""

        def __init__(self, inner):
            self.inner = inner

        async def handle_async_request(self, request):
            await self.inner.handle_async_request(request)
            raise httpx.ReadTimeout("simulated", request=request)

    w.overrides["aegissiem"] = LoseTheAnswer(httpx.ASGITransport(app=provider.app))
    first = await w.dispatch("threat_intel.lookup_ioc")
    assert (first["status"], first["outcome_unknown"]) == ("failed", True)
    assert len(provider.calls) == 1

    del w.overrides["aegissiem"]
    second = await w.dispatch("threat_intel.lookup_ioc")
    assert second["command_id"] == first["command_id"]
    assert second["status"] == "completed"
    assert second["outcome_unknown"] is False
    assert second["result"] == {"handled_by": "aegissiem", "subject": "192.168.1.20"}
    assert len(provider.calls) == 1  # the provider answered from its replay store


@pytest.mark.asyncio
async def test_definite_failure_is_not_retried_by_the_same_key(w):
    provider = w.add_provider("aegissiem", "threat_intel.lookup_ioc")
    w.overrides["aegissiem"] = Failing(status=500)
    first = await w.dispatch("threat_intel.lookup_ioc")
    assert first["status"] == "failed"
    assert "500" in first["error"]
    assert first["outcome_unknown"] is False
    del w.overrides["aegissiem"]
    second = await w.dispatch("threat_intel.lookup_ioc")
    assert second["status"] == "failed"
    assert provider.calls == []


@pytest.mark.asyncio
async def test_provider_answer_that_is_not_the_contract_is_failed(w):
    w.add_provider("aegissiem", "threat_intel.lookup_ioc")

    class Nonsense(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            return httpx.Response(200, json={"status": "totally_done", "result": {"x": 1}})

    w.overrides["aegissiem"] = Nonsense()
    out = await w.dispatch("threat_intel.lookup_ioc")
    assert out["status"] == "failed"
    assert out["outcome_unknown"] is True


@pytest.mark.asyncio
async def test_caller_context_cannot_inject_approval_or_budget_keys(w):
    w.add_provider("aegissiem", "threat_intel.lookup_ioc")
    seen = []
    real_decide = w.engine.decide

    def spy(req, **kw):
        seen.append(req)
        return real_decide(req, **kw)

    w.engine.decide = spy
    await w.dispatch(
        "threat_intel.lookup_ioc",
        context={
            "trigger": "schedule",
            "incident_id": "INC-7",
            "profile": "quick",
            "approved_data_release_id": "forged",
            "budget_exceeded": False,
            "classification": "public",
            "command_id": "forged",
        },
    )
    ctx = seen[0].context
    assert ctx["trigger"] == "schedule"
    assert ctx["incident_id"] == "INC-7"
    assert ctx["profile"] == "quick"
    assert "approved_data_release_id" not in ctx
    assert "budget_exceeded" not in ctx
    assert "classification" not in ctx
    assert ctx["command_id"] != "forged"
    assert seen[0].action == "lookup_ioc"
    assert seen[0].actor == "ai_for_survival/blue-team"


@pytest.mark.asyncio
async def test_caller_cannot_claim_a_less_restricted_trigger(w):
    w.add_provider("aegissiem", "threat_intel.lookup_ioc")
    seen = []
    real_decide = w.engine.decide
    w.engine.decide = lambda req, **kw: (seen.append(req), real_decide(req, **kw))[1]
    await w.dispatch(
        "threat_intel.lookup_ioc",
        actor={**ACTOR, "type": "automation"},
        context={"trigger": "operator"},
    )
    assert seen[0].context["trigger"] == "automation"


@pytest.mark.asyncio
async def test_allow_and_notify_routes_one_notification(w):
    w.add_provider("aegissiem", "threat_intel.lookup_ioc", "investigate")
    out = await w.dispatch("threat_intel.lookup_ioc", target={"scope": "external", "identifier": "8.8.8.8"})
    assert out["status"] == "completed"
    assert len(w.notifications.routed) == 1
    note = w.notifications.routed[0]
    assert note["type"] == "notify.command"
    assert note["dedupe_key"] == f"command:{out['command_id']}"


@pytest.mark.asyncio
async def test_notification_failure_does_not_change_outcome(w):
    w.add_provider("aegissiem", "threat_intel.lookup_ioc", "investigate")
    w.dispatcher = w.make_dispatcher(notification_router=FakeNotifications(fail=True))
    out = await w.dispatch("threat_intel.lookup_ioc", target={"scope": "external", "identifier": "8.8.8.8"})
    assert out["status"] == "completed"


@pytest.mark.asyncio
async def test_policy_engine_error_fails_closed(w):
    provider = w.add_provider("aegissiem", "threat_intel.lookup_ioc")

    def explode(req, **kw):
        raise RuntimeError("policy file unreadable")

    w.engine.decide = explode
    out = await w.dispatch("threat_intel.lookup_ioc")
    assert out["status"] == "denied"
    assert provider.envelopes == []


@pytest.mark.asyncio
async def test_missing_secret_sends_nothing(w):
    provider = w.add_provider("aegissiem", "threat_intel.lookup_ioc")
    w.dispatcher._secret_fn = lambda: ""
    out = await w.dispatch("threat_intel.lookup_ioc")
    assert out["status"] == "failed"
    assert provider.envelopes == []


@pytest.mark.asyncio
async def test_concurrent_duplicates_execute_once(w):
    provider = w.add_provider("aegissiem", "threat_intel.lookup_ioc")
    a, b = await asyncio.gather(w.dispatch("threat_intel.lookup_ioc"), w.dispatch("threat_intel.lookup_ioc"))
    assert a["command_id"] == b["command_id"]
    assert len(provider.calls) == 1


@pytest.mark.asyncio
async def test_retry_after_unknown_outcome_is_re_evaluated(w):
    provider = w.add_provider("aegissiem", "threat_intel.lookup_ioc")
    w.overrides["aegissiem"] = Failing(httpx.ReadTimeout)
    first = await w.dispatch("threat_intel.lookup_ioc", target={"scope": "local", "identifier": "192.168.1.20"})
    assert (first["status"], first["outcome_unknown"]) == ("failed", True)
    del w.overrides["aegissiem"]

    # The hub is frozen before the retry: observation is still allowed...
    w.engine.freeze(initiated_by="test")
    still_ok = await w.dispatch("threat_intel.lookup_ioc")
    assert still_ok["status"] == "completed"


@pytest.mark.asyncio
async def test_retry_after_unknown_outcome_is_refused_when_policy_now_denies(w):
    provider = w.add_provider("aegissiem", "containment.block_ip", "contain")
    w.overrides["aegissiem"] = Failing(httpx.ReadTimeout)
    first = await w.dispatch("containment.block_ip", target={"scope": "local", "identifier": "203.0.113.9"})
    assert (first["status"], first["outcome_unknown"]) == ("failed", True)
    sent_before = w.overrides["aegissiem"].requests
    del w.overrides["aegissiem"]

    w.engine.freeze(initiated_by="test")
    second = await w.dispatch("containment.block_ip", target={"scope": "local", "identifier": "203.0.113.9"})
    assert second["command_id"] == first["command_id"]
    assert (second["status"], second["outcome_unknown"]) == ("failed", True)
    assert provider.envelopes == [] and sent_before == 1
    events = [e["event"] for e in w.store.get(first["command_id"])["events"]]
    assert events[-1] == "retry_refused"


@pytest.mark.asyncio
async def test_actor_app_must_be_the_requester(w):
    from registry.commands import InvalidCommand

    provider = w.add_provider("aegissiem", "threat_intel.lookup_ioc")
    with pytest.raises(InvalidCommand):
        await w.dispatch("threat_intel.lookup_ioc", actor={**ACTOR, "app": "aegissiem"})
    assert provider.envelopes == []
    assert w.store.list() == []


# ---- final review ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_retry_after_unknown_outcome_is_refused_once_too_old(w):
    from ecosystem_hub.command_common import RETRY_WINDOW_SECONDS

    provider = w.add_provider("aegissiem", "threat_intel.lookup_ioc")
    clock = {"now": 1_800_000_000.0}
    w.dispatcher = w.make_dispatcher()
    w.dispatcher._clock = lambda: clock["now"]
    w.overrides["aegissiem"] = Failing(httpx.ReadTimeout)
    first = await w.dispatch("threat_intel.lookup_ioc")
    assert first["outcome_unknown"] is True
    del w.overrides["aegissiem"]

    clock["now"] = w.store.get(first["command_id"])["created_at"] + RETRY_WINDOW_SECONDS + 1
    second = await w.dispatch("threat_intel.lookup_ioc")
    assert (second["status"], second["outcome_unknown"]) == ("failed", True)
    assert provider.envelopes == []
    last = w.store.get(first["command_id"])["events"][-1]
    assert last["event"] == "retry_refused"
    assert "too old" in last["detail"]["reason"]


@pytest.mark.asyncio
async def test_caller_cannot_supply_the_reserved_policy_parameter(w):
    from registry.commands import InvalidCommand

    w.add_provider("aegissiem", "threat_intel.lookup_ioc")
    with pytest.raises(InvalidCommand):
        await w.dispatch("threat_intel.lookup_ioc", parameters={"_policy": {"incident_id": "forged"}})
    assert w.store.list() == []


@pytest.mark.asyncio
async def test_both_gates_see_the_same_policy_context(w):
    provider = w.add_provider("aegissiem", "threat_intel.lookup_ioc")
    hub_seen, provider_seen = [], []
    real_hub, real_provider = w.engine.decide, provider.engine.decide
    w.engine.decide = lambda req, **kw: (hub_seen.append(req), real_hub(req, **kw))[1]
    provider.engine.decide = lambda req, **kw: (provider_seen.append(req), real_provider(req, **kw))[1]
    out = await w.dispatch(
        "threat_intel.lookup_ioc",
        context={"trigger": "schedule", "incident_id": "INC-7", "profile": "full"},
    )
    assert out["status"] == "completed"
    assert hub_seen[0].context == provider_seen[0].context
    assert hub_seen[0].action == provider_seen[0].action
    assert hub_seen[0].target == provider_seen[0].target
    assert provider.calls[0].parameters == {"indicator": "192.168.1.20"}


@pytest.mark.asyncio
async def test_unexpected_forwarding_error_does_not_leave_the_command_dispatching(w):
    w.add_provider("aegissiem", "threat_intel.lookup_ioc")

    class Broken(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            raise ValueError("something nobody expected")

    w.overrides["aegissiem"] = Broken()
    out = await w.dispatch("threat_intel.lookup_ioc")
    assert out["status"] == "failed"
    assert out["outcome_unknown"] is True
    assert w.store.get(out["command_id"])["events"][-1]["event"] == "forward_error"


@pytest.mark.asyncio
async def test_a_late_approval_on_a_closed_command_is_not_recorded_as_granted(w):
    provider = w.add_provider("aegissiem", "network.inspect_host", "investigate")
    doc = await w.dispatch("network.inspect_host", parameters={"host": "192.168.1.20"})
    approval = {"approval_id": doc["approval_id"], "async_containment": False}
    w.dispatcher.mark_approval_closed(approval, outcome="denied")
    out = await w.dispatcher.execute_approved(approval)
    assert out["status"] == "denied"
    events = [e["event"] for e in w.store.get(doc["command_id"])["events"]]
    assert "approval_granted" not in events
    assert events[-1] == "approval_arrived_late"
    assert provider.envelopes == []
