import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from ecosystem_client.contracts import Proposal
from ecosystem_hub.action_loop import ActionStep, ActionTimeline, run_action_loop
from ecosystem_policy.models import PolicyDecision


class FakePolicy:
    def __init__(self, decisions=None, frozen=False):
        self._decisions = list(decisions or [])
        self._frozen = frozen
        self.recorded_requests = []

    def frozen(self):
        return self._frozen

    def set_frozen(self, val: bool):
        self._frozen = val

    def decide(self, req):
        self.recorded_requests.append(req)
        if self._decisions:
            return self._decisions.pop(0)
        return PolicyDecision(
            result="allow",
            reason="allowed by default",
            policy_version=1,
            mode="normal",
            restrictions="on",
            frozen=self._frozen,
        )


class FakeHub:
    def __init__(self, responses=None):
        self._responses = list(responses or [])
        self.invocations = []

    async def invoke(self, capability, target, parameters=None, rationale=None, idempotency_key=None, **kwargs):
        self.invocations.append({
            "capability": capability,
            "target": target,
            "parameters": parameters,
            "rationale": rationale,
            "idempotency_key": idempotency_key,
        })
        if self._responses:
            resp = self._responses.pop(0)
            if isinstance(resp, Exception):
                raise resp
            return resp
        return {
            "status": "completed",
            "command_id": "01HQXYZ123456789ABCDEF",
            "result": {"confirmed": True},
        }


@pytest.mark.asyncio
async def test_normal_action_loop_executes_allowed_proposals():
    rounds = 0

    async def analyst(req, ctx):
        nonlocal rounds
        rounds += 1
        if rounds == 1:
            return json.dumps({
                "proposals": [
                    {
                        "action": "threat_intel.lookup_ioc",
                        "action_class": "observe",
                        "target": "203.0.113.19",
                        "parameters": {"type": "ip"},
                        "rationale": "Check reputation of suspicious source",
                        "confidence": 0.9,
                    }
                ]
            })
        return json.dumps({"proposals": []})

    policy = FakePolicy()
    hub = FakeHub()

    timeline = await run_action_loop(
        "Investigate 203.0.113.19",
        analyst=analyst,
        policy=policy,
        hub=hub,
    )

    assert timeline.completed is True
    assert timeline.stopped_reason == "no_more_proposals" or timeline.stopped_reason == "completed"
    assert len(timeline.steps) == 1
    step = timeline.steps[0]
    assert step.decision == "allow"
    assert step.status == "completed"
    assert step.command_id == "01HQXYZ123456789ABCDEF"
    assert len(hub.invocations) == 1
    assert hub.invocations[0]["capability"] == "threat_intel.lookup_ioc"


@pytest.mark.asyncio
async def test_invariant_1_denied_proposal_is_never_dispatched():
    async def analyst(req, ctx):
        return json.dumps({
            "proposals": [
                {
                    "action": "containment.block_ip",
                    "action_class": "contain",
                    "target": "8.8.8.8",
                    "parameters": {},
                    "rationale": "Block recursive resolver",
                    "confidence": 0.5,
                }
            ]
        })

    deny_decision = PolicyDecision(
        result="deny",
        reason="Target 8.8.8.8 is a critical public infrastructure service outside scope",
        policy_version=1,
        mode="normal",
        restrictions="on",
        frozen=False,
    )
    policy = FakePolicy(decisions=[deny_decision])
    hub = FakeHub()

    timeline = await run_action_loop(
        "Block 8.8.8.8",
        analyst=analyst,
        policy=policy,
        hub=hub,
    )

    assert timeline.completed is True
    assert len(timeline.steps) == 1
    step = timeline.steps[0]
    assert step.decision == "deny"
    assert step.status == "denied"
    assert "critical public infrastructure" in step.decision_reason
    # Invariant 1: HUB.INVOKE WAS NEVER CALLED!
    assert len(hub.invocations) == 0


@pytest.mark.asyncio
async def test_invariant_1_approval_pending_proposal_is_never_dispatched():
    async def analyst(req, ctx):
        return json.dumps({
            "proposals": [
                {
                    "action": "system.restart_service",
                    "action_class": "remediate",
                    "target": "host1",
                    "parameters": {"service": "nginx"},
                    "rationale": "Restart degraded web service",
                    "confidence": 0.8,
                }
            ]
        })

    approval_decision = PolicyDecision(
        result="require_approval",
        reason="Remediate actions require step-up authorization",
        policy_version=1,
        mode="normal",
        restrictions="on",
        frozen=False,
        grant_id="appr-step-999",
    )
    policy = FakePolicy(decisions=[approval_decision])
    hub = FakeHub()

    timeline = await run_action_loop(
        "Restart nginx",
        analyst=analyst,
        policy=policy,
        hub=hub,
    )

    assert timeline.completed is True
    assert len(timeline.steps) == 1
    step = timeline.steps[0]
    assert step.decision == "require_approval"
    assert step.status == "pending_approval"
    assert step.approval_id == "appr-step-999"
    # Invariant 1: HUB.INVOKE WAS NEVER CALLED!
    assert len(hub.invocations) == 0


@pytest.mark.asyncio
async def test_invariant_2_initial_freeze_halts_immediately():
    analyst = AsyncMock()
    policy = FakePolicy(frozen=True)
    hub = FakeHub()

    timeline = await run_action_loop(
        "Do anything",
        analyst=analyst,
        policy=policy,
        hub=hub,
    )

    assert timeline.completed is True
    assert timeline.stopped_reason == "frozen"
    assert len(timeline.steps) == 0
    analyst.assert_not_called()
    assert len(hub.invocations) == 0


@pytest.mark.asyncio
async def test_invariant_2_mid_loop_freeze_halts_remaining_steps():
    async def analyst(req, ctx):
        return json.dumps({
            "proposals": [
                {
                    "action": "threat_intel.lookup_ioc",
                    "action_class": "observe",
                    "target": "203.0.113.1",
                    "parameters": {},
                    "rationale": "Step 1",
                    "confidence": 0.9,
                },
                {
                    "action": "containment.block_ip",
                    "action_class": "contain",
                    "target": "203.0.113.1",
                    "parameters": {},
                    "rationale": "Step 2",
                    "confidence": 0.9,
                },
            ]
        })

    policy = FakePolicy()
    hub = FakeHub()

    # Freeze the policy after the first invoke
    orig_invoke = hub.invoke

    async def freeze_on_first_invoke(*args, **kwargs):
        res = await orig_invoke(*args, **kwargs)
        policy.set_frozen(True)
        return res

    hub.invoke = freeze_on_first_invoke

    timeline = await run_action_loop(
        "Multi-step mitigation",
        analyst=analyst,
        policy=policy,
        hub=hub,
    )

    assert timeline.completed is True
    assert timeline.stopped_reason == "frozen"
    assert len(timeline.steps) == 2
    assert timeline.steps[0].status == "completed"
    # Invariant 2: Step 2 was halted by Freeze
    assert timeline.steps[1].status == "skipped_frozen"
    assert timeline.steps[1].decision == "frozen"
    # Hub was only invoked once!
    assert len(hub.invocations) == 1


@pytest.mark.asyncio
async def test_invariant_3_max_steps_bounds_iteration():
    # Looping analyst that keeps proposing steps
    async def analyst(req, ctx):
        return json.dumps({
            "proposals": [
                {
                    "action": "threat_intel.lookup_ioc",
                    "action_class": "observe",
                    "target": "203.0.113.5",
                    "parameters": {},
                    "rationale": "Looping check",
                    "confidence": 0.9,
                }
            ]
        })

    policy = FakePolicy()
    hub = FakeHub()

    timeline = await run_action_loop(
        "Run forever",
        analyst=analyst,
        policy=policy,
        hub=hub,
        max_steps=3,
    )

    assert timeline.completed is True
    assert timeline.stopped_reason == "max_steps_exceeded"
    # Exactly max_steps executed
    assert len(timeline.steps) == 3
    assert len(hub.invocations) == 3


@pytest.mark.asyncio
async def test_invariant_4_provider_error_preserved_in_timeline():
    rounds = 0

    async def analyst(req, ctx):
        nonlocal rounds
        rounds += 1
        if rounds == 1:
            return json.dumps({
                "proposals": [
                    {
                        "action": "containment.block_ip",
                        "action_class": "contain",
                        "target": "203.0.113.10",
                        "parameters": {},
                        "rationale": "Block attacker",
                        "confidence": 0.9,
                    }
                ]
            })
        return json.dumps({"proposals": []})

    policy = FakePolicy()
    # Hub raises connection error
    hub = FakeHub(responses=[RuntimeError("Connection refused by router endpoint")])

    timeline = await run_action_loop(
        "Block attacker",
        analyst=analyst,
        policy=policy,
        hub=hub,
    )

    assert timeline.completed is True
    assert len(timeline.steps) == 1
    step = timeline.steps[0]
    assert step.decision == "allow"
    # Invariant 4: step status records failure with error message, timeline survives intact
    assert step.status == "failed"
    assert "Connection refused by router endpoint" in step.error


@pytest.mark.asyncio
async def test_unusable_analyst_output_fails_closed():
    async def bad_analyst(req, ctx):
        return "I am unable to provide structured JSON for this security task."

    policy = FakePolicy()
    hub = FakeHub()

    timeline = await run_action_loop(
        "Bad request",
        analyst=bad_analyst,
        policy=policy,
        hub=hub,
    )

    assert timeline.completed is True
    assert timeline.stopped_reason == "unusable_model_output"
    assert len(timeline.steps) == 0
    assert len(hub.invocations) == 0


@pytest.mark.asyncio
async def test_timeline_and_step_to_dict_serialization():
    p = Proposal(
        action="containment.block_ip",
        action_class="contain",
        target="192.168.1.50",
        parameters={"ttl": 1800},
        rationale="Isolate host",
        confidence=0.95,
    )
    step = ActionStep(
        step_number=1,
        proposal=p,
        decision="allow",
        decision_reason="Approved",
        command_id="cmd-1",
        status="completed",
        result={"blocked": True},
    )
    d = step.to_dict()
    assert d["step_number"] == 1
    assert d["proposal"]["action"] == "containment.block_ip"
    assert d["result"] == {"blocked": True}

    tl = ActionTimeline(session_id="sess-1", request="Test req", steps=[step], completed=True)
    tl_dict = tl.to_dict()
    assert tl_dict["session_id"] == "sess-1"
    assert len(tl_dict["steps"]) == 1


@pytest.mark.asyncio
async def test_action_loop_with_real_policy_engine():
    from ecosystem_policy.engine import PolicyEngine

    pe = PolicyEngine()
    assert isinstance(pe.frozen, bool)
    assert pe.frozen is False

    rounds = 0

    async def analyst(req, ctx):
        nonlocal rounds
        rounds += 1
        if rounds == 1:
            return json.dumps({
                "proposals": [
                    {
                        "action": "threat_intel.lookup_ioc",
                        "action_class": "observe",
                        "target": "192.168.1.20",
                        "parameters": {},
                        "rationale": "Internal audit",
                        "confidence": 0.9,
                    }
                ]
            })
        return json.dumps({"proposals": []})

    hub = FakeHub()
    tl = await run_action_loop("Check local device", analyst=analyst, policy=pe, hub=hub)
    assert tl.completed is True
    assert len(tl.steps) == 1
    assert tl.steps[0].decision in ("allow", "allow_and_notify")

    pe.freeze(initiated_by="admin", reason="Test emergency")
    assert pe.frozen is True
    tl_frozen = await run_action_loop("Check local device", analyst=analyst, policy=pe, hub=hub)
    assert tl_frozen.completed is True
    assert tl_frozen.stopped_reason == "frozen"


@pytest.mark.asyncio
async def test_action_loop_normalizes_command_target_with_scope_and_identifier():
    rounds = 0

    async def analyst(req, ctx):
        nonlocal rounds
        rounds += 1
        if rounds == 1:
            return json.dumps({
                "proposals": [
                    {
                        "action": "threat_intel.lookup_ioc",
                        "action_class": "observe",
                        "target": "203.0.113.19",
                        "parameters": {},
                        "rationale": "Check external IP",
                        "confidence": 0.9,
                    }
                ]
            })
        return json.dumps({"proposals": []})

    policy = FakePolicy()
    hub = FakeHub()

    tl = await run_action_loop("Check 203.0.113.19", analyst=analyst, policy=policy, hub=hub)
    assert tl.completed is True
    assert len(hub.invocations) == 1
    dispatched_target = hub.invocations[0]["target"]
    assert dispatched_target["scope"] == "external"
    assert dispatched_target["identifier"] == "203.0.113.19"
    assert "target" not in dispatched_target

    req = policy.recorded_requests[0]
    assert req.target["is_external"] is True
    assert req.target["host"] == "203.0.113.19"


@pytest.mark.asyncio
async def test_action_loop_creates_approval_queue_record_on_require_approval(tmp_path, monkeypatch):
    from ecosystem_policy.approval_queue import LocalApprovalQueue, default_approval_db_path

    monkeypatch.setenv("ECOSYSTEM_DATA_DIR", str(tmp_path))

    rounds = 0

    async def analyst(req, ctx):
        nonlocal rounds
        rounds += 1
        if rounds == 1:
            return json.dumps({
                "proposals": [
                    {
                        "action": "system.reboot",
                        "action_class": "remediate",
                        "target": "server-1",
                        "parameters": {},
                        "rationale": "Emergency reboot",
                        "confidence": 0.85,
                    }
                ]
            })
        return json.dumps({"proposals": []})

    policy_dec = PolicyDecision(
        result="require_approval",
        reason="Reboot requires human authorization",
        policy_version=3,
        mode="normal",
        restrictions="on",
        frozen=False,
    )
    policy = FakePolicy(decisions=[policy_dec])
    hub = FakeHub()

    tl = await run_action_loop("Reboot", analyst=analyst, policy=policy, hub=hub)
    assert tl.completed is True
    step = tl.steps[0]
    assert step.decision == "require_approval"
    assert step.status == "pending_approval"
    assert step.approval_id is not None
    assert len(step.approval_id) > 10

    # LocalApprovalQueue uses default_approval_db_path("action_loop") or ("hub")
    q = LocalApprovalQueue(db_path=default_approval_db_path("hub"))
    rec = q.get(step.approval_id)
    assert rec is not None
    assert rec["action"] == "system.reboot"
    assert rec["status"] == "pending"
    assert len(hub.invocations) == 0


@pytest.mark.asyncio
async def test_action_loop_halts_on_outcome_unknown_for_reconciliation():
    async def analyst(req, ctx):
        return json.dumps({
            "proposals": [
                {
                    "action": "containment.block_ip",
                    "action_class": "contain",
                    "target": "203.0.113.55",
                    "parameters": {},
                    "rationale": "Block attacker",
                    "confidence": 0.9,
                }
            ]
        })

    policy = FakePolicy()
    hub = FakeHub(responses=[{
        "status": "failed",
        "command_id": "cmd-unk-1",
        "outcome_unknown": True,
        "error": "Timeout while waiting for provider ACK",
    }])

    tl = await run_action_loop("Block attacker", analyst=analyst, policy=policy, hub=hub)
    assert tl.completed is True
    assert tl.stopped_reason == "reconciliation_needed"
    assert "unknown outcome" in tl.error
    assert len(tl.steps) == 1
    step = tl.steps[0]
    assert step.outcome_unknown is True
    assert step.status == "failed"
    assert step.idempotency_key is not None


@pytest.mark.asyncio
@pytest.mark.parametrize("is_async", [False, True])
async def test_action_loop_invokes_step_callback(is_async: bool):
    async def analyst(req, ctx):
        if ctx.get("prior_steps"):
            return json.dumps({"proposals": []})
        return json.dumps({
            "proposals": [
                {
                    "action": "threat_intel.lookup_ioc",
                    "action_class": "observe",
                    "target": "192.168.1.10",
                    "parameters": {},
                    "rationale": "Lookup",
                    "confidence": 0.9,
                }
            ]
        })

    policy = FakePolicy()
    hub = FakeHub(responses=[{"status": "completed", "result": {"verdict": "suspicious"}}])

    recorded_steps = []

    if is_async:
        async def callback(step):
            await asyncio.sleep(0)
            recorded_steps.append(step)
    else:
        def callback(step):
            recorded_steps.append(step)

    tl = await run_action_loop(
        "Lookup IP",
        analyst=analyst,
        policy=policy,
        hub=hub,
        step_callback=callback,
    )
    assert tl.completed is True
    assert len(recorded_steps) == 1
    assert recorded_steps[0].proposal.action == "threat_intel.lookup_ioc"
    assert recorded_steps[0].status == "completed"

