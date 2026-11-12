"""Provider side of command dispatch: verify, replay check, second policy gate, handler."""
from __future__ import annotations

import asyncio

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ecosystem_auth.tokens import sign_payload
from ecosystem_client.contracts import build_command_envelope, canonical_signable_command
from ecosystem_hub.command_common import is_internal_subject, policy_target, request_digest
from ecosystem_hub.command_receiver import (
    Accepted,
    CommandFailed,
    CommandReceiver,
    HubApprovalVerifier,
    build_command_router,
)
from ecosystem_policy import PolicyEngine

SECRET = "receiver-test-secret-0123456789abcdef"
ACTOR = {"id": "blue-team", "type": "service", "app": "ai_for_survival", "device_id": "local-device"}


class Harness:
    def __init__(self, tmp_path, *, verifier=None, now_fn=None):
        self.engine = PolicyEngine(authority="hub_synced")
        self.calls: list = []
        kwargs = {"now_fn": now_fn} if now_fn else {}
        self.receiver = CommandReceiver(
            "aegissiem",
            secret=SECRET,
            policy_engine=self.engine,
            replay_db_path=tmp_path / "replay.db",
            approval_verifier=verifier,
            **kwargs,
        )
        self.receiver.register("threat_intel.lookup_ioc", "observe", self._lookup)
        self.receiver.register("network.inspect_host", "investigate", self._lookup)
        self.receiver.register("containment.block_ip", "contain", self._lookup)

    async def _lookup(self, ctx):
        self.calls.append(ctx)
        return {"verdict": "clean", "subject": ctx.target.get("identifier")}


def envelope(command="threat_intel.lookup_ioc", action_class="observe", *, target=None, parameters=None,
             key="key-1", secret=SECRET, authorization_ref=None, **kw):
    return build_command_envelope(
        command,
        action_class,
        ACTOR,
        target or {"scope": "local", "identifier": "192.168.1.20"},
        secret,
        parameters=parameters if parameters is not None else {"indicator": "192.168.1.20"},
        idempotency_key=key,
        authorization_ref=authorization_ref,
        rationale="test",
        **kw,
    )


@pytest.fixture
def h(tmp_path):
    return Harness(tmp_path)


@pytest.mark.asyncio
async def test_valid_command_runs_handler_and_completes(h):
    env = envelope()
    status, body = await h.receiver.handle(env)
    assert status == 200
    assert body["status"] == "completed"
    assert body["command_id"] == env["id"]
    assert body["result"] == {"verdict": "clean", "subject": "192.168.1.20"}
    assert body["duplicate"] is False
    assert body["decision"]["result"] == "allow"
    assert len(h.calls) == 1
    ctx = h.calls[0]
    assert (ctx.command, ctx.action_class, ctx.actor["app"]) == ("threat_intel.lookup_ioc", "observe", "ai_for_survival")
    assert ctx.parameters == {"indicator": "192.168.1.20"}


@pytest.mark.asyncio
async def test_unsigned_envelope_is_rejected(h):
    env = envelope()
    del env["signature"]
    status, body = await h.receiver.handle(env)
    assert status == 401
    assert h.calls == []


@pytest.mark.asyncio
async def test_non_object_body_is_rejected(h):
    status, _ = await h.receiver.handle(["not", "an", "envelope"])
    assert status == 401


@pytest.mark.asyncio
async def test_envelope_signed_with_other_secret_is_rejected(h):
    status, body = await h.receiver.handle(envelope(secret="some-other-secret-0123456789abcdef"))
    assert status == 401
    assert "signature" in body["error"]
    assert h.calls == []


@pytest.mark.asyncio
async def test_expired_envelope_is_rejected(tmp_path):
    env = envelope(ttl_seconds=30)
    late = Harness(tmp_path, now_fn=lambda: env["expires_at"] + 1)
    status, body = await late.receiver.handle(env)
    assert status == 401
    assert body["error"] == "command expired"
    assert late.calls == []


@pytest.mark.asyncio
async def test_tampered_parameters_are_rejected(h):
    env = envelope()
    env["parameters"] = {"indicator": "10.0.0.1"}
    status, _ = await h.receiver.handle(env)
    assert status == 401
    assert h.calls == []


@pytest.mark.asyncio
async def test_notification_ref_cannot_authorize(h):
    env = envelope()
    env["authorization_ref"] = "notify:01HZX"
    env["signature"] = sign_payload(canonical_signable_command(env), SECRET)
    status, body = await h.receiver.handle(env)
    assert status == 401
    assert "notification" in body["error"]
    assert h.calls == []


@pytest.mark.asyncio
async def test_duplicate_idempotency_key_returns_first_result(h):
    first = envelope()
    _, body1 = await h.receiver.handle(first)
    # A retry is a new envelope (new id, new signature) carrying the same key and request.
    status, body2 = await h.receiver.handle(envelope())
    assert status == 200
    assert body2["duplicate"] is True
    assert body2["status"] == "completed"
    assert body2["result"] == body1["result"]
    assert body2["command_id"] == first["id"]
    assert len(h.calls) == 1


@pytest.mark.asyncio
async def test_same_key_with_different_parameters_conflicts(h):
    await h.receiver.handle(envelope())
    status, _ = await h.receiver.handle(envelope(parameters={"indicator": "192.168.1.99"}))
    assert status == 409
    assert len(h.calls) == 1


@pytest.mark.asyncio
async def test_same_key_from_another_requester_is_independent(h):
    await h.receiver.handle(envelope())
    other = build_command_envelope(
        "threat_intel.lookup_ioc", "observe", {**ACTOR, "app": "cyber_harness"},
        {"scope": "local", "identifier": "192.168.1.20"}, SECRET,
        parameters={"indicator": "192.168.1.20"}, idempotency_key="key-1",
    )
    status, body = await h.receiver.handle(other)
    assert (status, body["duplicate"]) == (200, False)
    assert len(h.calls) == 2


@pytest.mark.asyncio
async def test_command_still_running_conflicts(tmp_path):
    h = Harness(tmp_path)
    started, release = asyncio.Event(), asyncio.Event()

    async def slow(ctx):
        started.set()
        await release.wait()
        return {"ok": True}

    h.receiver.register("camera.snapshot", "observe", slow)
    first = asyncio.create_task(h.receiver.handle(envelope("camera.snapshot")))
    await started.wait()
    status, body = await h.receiver.handle(envelope("camera.snapshot"))
    assert status == 409
    assert body["outcome_unknown"] is True
    release.set()
    assert (await first)[1]["status"] == "completed"


@pytest.mark.asyncio
async def test_command_for_another_service_is_not_found(h):
    status, _ = await h.receiver.handle(envelope(target={"scope": "local", "service": "openeye"}))
    assert status == 404
    assert h.calls == []


@pytest.mark.asyncio
async def test_command_addressed_to_this_service_runs(h):
    status, body = await h.receiver.handle(envelope(target={"scope": "local", "service": "aegissiem"}))
    assert (status, body["status"]) == (200, "completed")


@pytest.mark.asyncio
async def test_unknown_command_is_not_found(h):
    status, _ = await h.receiver.handle(envelope("camera.record_clip"))
    assert status == 404


@pytest.mark.asyncio
async def test_action_class_mismatch_is_denied(h):
    # The caller labels a containment as a harmless observation.
    status, body = await h.receiver.handle(envelope("containment.block_ip", "observe"))
    assert (status, body["status"]) == (200, "denied")
    assert "action class" in body["error"]
    assert h.calls == []


@pytest.mark.asyncio
async def test_frozen_provider_refuses(h):
    h.engine.freeze(initiated_by="test")
    status, body = await h.receiver.handle(envelope("containment.block_ip", "contain"))
    assert (status, body["status"]) == (200, "denied")
    assert body["decision"]["frozen"] is True
    assert h.calls == []


@pytest.mark.asyncio
async def test_provisional_containment_runs_at_gate_two(h):
    status, body = await h.receiver.handle(
        envelope("containment.block_ip", "contain", target={"scope": "local", "identifier": "203.0.113.9"})
    )
    assert (status, body["status"]) == (200, "completed")
    assert body["decision"]["async_approval"] is True


@pytest.mark.asyncio
async def test_gate2_denies_external_subject_for_investigate(h):
    status, body = await h.receiver.handle(
        envelope("network.inspect_host", "investigate", target={"scope": "local", "identifier": "8.8.8.8"})
    )
    assert (status, body["status"]) == (200, "denied")
    assert body["decision"]["result"] == "deny"
    assert h.calls == []


@pytest.mark.asyncio
async def test_require_approval_without_reference_is_denied(h):
    status, body = await h.receiver.handle(envelope("network.inspect_host", "investigate"))
    assert (status, body["status"]) == (200, "denied")
    assert body["error"] == "approval required"
    assert h.calls == []


@pytest.mark.asyncio
async def test_require_approval_with_verified_reference_runs(tmp_path):
    seen = []

    async def verifier(env):
        seen.append(env["authorization_ref"])
        return True

    h = Harness(tmp_path, verifier=verifier)
    status, body = await h.receiver.handle(
        envelope("network.inspect_host", "investigate", authorization_ref="approval:01HAPPROVAL")
    )
    assert (status, body["status"]) == (200, "completed")
    assert seen == ["approval:01HAPPROVAL"]
    assert len(h.calls) == 1


@pytest.mark.asyncio
async def test_require_approval_with_unverified_reference_is_denied(tmp_path):
    async def verifier(env):
        return False

    h = Harness(tmp_path, verifier=verifier)
    status, body = await h.receiver.handle(
        envelope("network.inspect_host", "investigate", authorization_ref="approval:forged")
    )
    assert (status, body["status"]) == (200, "denied")
    assert h.calls == []


@pytest.mark.asyncio
async def test_approval_reference_without_a_verifier_is_denied(h):
    status, body = await h.receiver.handle(
        envelope("network.inspect_host", "investigate", authorization_ref="approval:01HAPPROVAL")
    )
    assert body["status"] == "denied"
    assert h.calls == []


@pytest.mark.asyncio
async def test_verifier_that_raises_is_treated_as_refusal(tmp_path):
    async def verifier(env):
        raise RuntimeError("hub exploded")

    h = Harness(tmp_path, verifier=verifier)
    _, body = await h.receiver.handle(
        envelope("network.inspect_host", "investigate", authorization_ref="approval:01HAPPROVAL")
    )
    assert body["status"] == "denied"
    assert h.calls == []


@pytest.mark.asyncio
async def test_handler_failure_is_reported_as_failed(h):
    async def refuse(ctx):
        raise CommandFailed("router rejected rule", result={"rc": 2})

    h.receiver.register("camera.snapshot", "observe", refuse)
    status, body = await h.receiver.handle(envelope("camera.snapshot"))
    assert (status, body["status"]) == (200, "failed")
    assert body["error"] == "router rejected rule"
    assert body["result"] == {"rc": 2}
    assert body["outcome_unknown"] is False


@pytest.mark.asyncio
async def test_handler_timeout_is_failed_with_outcome_unknown(h):
    async def hang(ctx):
        await asyncio.sleep(5)

    h.receiver.register("camera.snapshot", "observe", hang, timeout_seconds=0.05)
    status, body = await h.receiver.handle(envelope("camera.snapshot"))
    assert (status, body["status"]) == (200, "failed")
    assert body["outcome_unknown"] is True


@pytest.mark.asyncio
async def test_handler_exception_does_not_leak_message(h):
    async def boom(ctx):
        raise RuntimeError("password=hunter2 at /Users/someone/.ssh/id_rsa")

    h.receiver.register("camera.snapshot", "observe", boom)
    _, body = await h.receiver.handle(envelope("camera.snapshot"))
    assert body["status"] == "failed"
    assert body["error"] == "RuntimeError"
    assert body["outcome_unknown"] is True


@pytest.mark.asyncio
async def test_accepted_handler_returns_accepted(h):
    async def start(ctx):
        return Accepted("job-42")

    h.receiver.register("camera.record_clip", "observe", start)
    _, body = await h.receiver.handle(envelope("camera.record_clip"))
    assert body["status"] == "accepted"
    assert body["result"] == {"job_ref": "job-42"}


@pytest.mark.asyncio
async def test_oversized_result_is_failed(h):
    async def big(ctx):
        return {"blob": "x" * 70_000}

    h.receiver.register("camera.snapshot", "observe", big)
    _, body = await h.receiver.handle(envelope("camera.snapshot"))
    assert body["status"] == "failed"
    assert body["error"] == "result too large"
    assert body["result"] is None


@pytest.mark.asyncio
async def test_non_dict_result_is_failed(h):
    async def wrong(ctx):
        return "done"

    h.receiver.register("camera.snapshot", "observe", wrong)
    _, body = await h.receiver.handle(envelope("camera.snapshot"))
    assert body["status"] == "failed"


@pytest.mark.asyncio
async def test_denied_outcome_is_replayed_not_re_evaluated(h):
    h.engine.freeze(initiated_by="test")
    await h.receiver.handle(envelope("containment.block_ip", "contain"))
    h.engine.resume(operator_id="admin", auth_method="totp")
    _, body = await h.receiver.handle(envelope("containment.block_ip", "contain"))
    # Same key, same answer: a new attempt needs a new idempotency key.
    assert (body["status"], body["duplicate"]) == ("denied", True)
    assert h.calls == []


def test_register_rejects_unknown_action_class(h):
    with pytest.raises(ValueError):
        h.receiver.register("camera.snapshot", "look_around", h._lookup)


def test_router_posts_to_ecosystem_commands(h):
    app = FastAPI()
    app.include_router(build_command_router(h.receiver))
    with TestClient(app) as client:
        ok = client.post("/ecosystem/commands", json=envelope())
        assert ok.status_code == 200
        assert ok.json()["status"] == "completed"
        bad = client.post("/ecosystem/commands", json={"command": "x"})
        assert bad.status_code == 401
        garbage = client.post("/ecosystem/commands", content=b"{not json", headers={"content-type": "application/json"})
        assert garbage.status_code == 401


@pytest.mark.parametrize(
    "subject",
    [
        "134744072", "0x08080808", "010.1.1.1", "::ffff:8.8.8.8", "8.8.8.8/32", "example.com", "nas",
        "2001:4860:4860::8888", "0.0.0.0/0", "192.168.0.0/15", "printer.local.evil.com", "user@host.local",
        "::ffff:0:0/96", "http://192.168.1.1/", "192.168.1.1:22", 3232235777,
    ],
)
def test_public_looking_subjects_are_external(subject):
    assert is_internal_subject(subject) is False


@pytest.mark.parametrize(
    "subject",
    [
        "192.168.1.20", "10.0.0.0/8", "172.16.5.4", "fe80::1", "fd00::5", "127.0.0.1", "::1", "169.254.10.10",
        "printer.local", "NAS.Home.Arpa.", "::ffff:192.168.1.5", None, "",
    ],
)
def test_private_subjects_are_internal(subject):
    assert is_internal_subject(subject) is True


def test_policy_target_marks_external_only_for_classes_that_touch_the_subject():
    public = {"scope": "local", "identifier": "203.0.113.9"}
    assert "is_external" not in policy_target(public, "contain")
    assert "is_external" not in policy_target(public, "observe")
    for cls in ("investigate", "remediate", "system_change"):
        mapped = policy_target(public, cls)
        assert mapped["is_external"] is True
        assert mapped["host"] == "203.0.113.9"
        assert mapped["kind"] == "external_ip"
    assert "is_external" not in policy_target({"scope": "device", "device_id": "mbp-01"}, "investigate")


def test_contain_is_external_when_the_scope_says_so():
    mapped = policy_target({"scope": "external", "identifier": "203.0.113.9"}, "contain")
    assert mapped["is_external"] is True


# ---- HubApprovalVerifier ------------------------------------------------------


def _fake_hub(record: dict | None, seen: list):
    app = FastAPI()

    @app.get("/commands/{command_id}")
    async def get_command(command_id: str):
        seen.append(command_id)
        if record is None:
            from fastapi import HTTPException

            raise HTTPException(status_code=404, detail="not found")
        return record

    return app


def _record(env, **over) -> dict:
    record = {
        "digest": _digest(env),
        "approval_id": "A1",
        "approval": {"status": "approved"},
        "status": "dispatching",
        "provider": "aegissiem",
        "capability": env["command"],
        "action_class": env["action_class"],
        "requester_app": env["actor"]["app"],
    }
    record.update(over)
    return record


def _verifier(app) -> HubApprovalVerifier:
    return HubApprovalVerifier(
        "http://hub.test",
        SECRET,
        app_name="aegissiem",
        client_factory=lambda: httpx.AsyncClient(transport=httpx.ASGITransport(app=app)),
    )


def _digest(env) -> str:
    return request_digest(env["command"], env["target"], env["parameters"])


@pytest.mark.asyncio
async def test_hub_approval_verifier_accepts_an_approved_matching_command():
    env = envelope("network.inspect_host", "investigate", authorization_ref="approval:A1")
    seen: list = []
    hub = _fake_hub(_record(env), seen)
    assert await _verifier(hub)(env) is True
    assert seen == [env["id"]]


@pytest.mark.asyncio
async def test_hub_approval_verifier_requires_matching_digest():
    env = envelope("network.inspect_host", "investigate", authorization_ref="approval:A1")
    hub = _fake_hub(_record(env, digest="0" * 64), [])
    assert await _verifier(hub)(env) is False


@pytest.mark.asyncio
async def test_hub_approval_verifier_requires_the_named_approval():
    env = envelope("network.inspect_host", "investigate", authorization_ref="approval:OTHER")
    hub = _fake_hub(_record(env), [])
    assert await _verifier(hub)(env) is False


@pytest.mark.asyncio
@pytest.mark.parametrize("approval", [{"status": "pending"}, {"status": "denied"}, {"status": "expired"}, None])
async def test_hub_approval_verifier_rejects_unapproved(approval):
    env = envelope("network.inspect_host", "investigate", authorization_ref="approval:A1")
    hub = _fake_hub(_record(env, approval=approval), [])
    assert await _verifier(hub)(env) is False


@pytest.mark.asyncio
async def test_hub_approval_verifier_accepts_pending_provisional_containment():
    env = envelope("containment.block_ip", "contain", authorization_ref="approval:A1")
    hub = _fake_hub(_record(env, approval={"status": "pending", "async_containment": True}), [])
    assert await _verifier(hub)(env) is True


@pytest.mark.asyncio
async def test_hub_approval_verifier_pending_path_is_only_for_containment():
    env = envelope("network.inspect_host", "investigate", authorization_ref="approval:A1")
    hub = _fake_hub(_record(env, approval={"status": "pending", "async_containment": True}), [])
    assert await _verifier(hub)(env) is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "override",
    [
        {"provider": "openeye"},            # approved for a different provider
        {"status": "completed"},            # already executed: an approval is used once
        {"status": "pending_approval"},     # the hub is not dispatching it
        {"status": "denied"},
        {"action_class": "observe"},        # the hub recorded a different class
        {"requester_app": "cyber_harness"}, # approved for a different requester
        {"capability": "camera.snapshot"},
    ],
)
async def test_hub_approval_verifier_binds_the_approval_to_this_execution(override):
    env = envelope("network.inspect_host", "investigate", authorization_ref="approval:A1")
    hub = _fake_hub(_record(env, **override), [])
    assert await _verifier(hub)(env) is False


@pytest.mark.asyncio
async def test_hub_approval_verifier_fails_closed_when_command_unknown():
    env = envelope("network.inspect_host", "investigate", authorization_ref="approval:A1")
    assert await _verifier(_fake_hub(None, []))(env) is False


@pytest.mark.asyncio
async def test_hub_approval_verifier_fails_closed_when_hub_unreachable():
    env = envelope("network.inspect_host", "investigate", authorization_ref="approval:A1")
    # No transport override: the suite's network guard refuses the connection.
    verifier = HubApprovalVerifier("http://127.0.0.1:8500", SECRET, app_name="aegissiem")
    assert await verifier(env) is False


# ---- the action name the policy sees ------------------------------------------


def test_policy_action_is_the_capability_unless_explicitly_aliased():
    from ecosystem_hub.command_common import policy_action

    # The engine matches some names exactly (its scan-consent check looks for "scan.request"),
    # so the capability id is passed through untouched...
    assert policy_action("scan.request", "investigate") == "scan.request"
    assert policy_action("containment.block_ip", "contain") == "containment.block_ip"
    # ...except for the passive lookups the policy lists by bare name, and only
    # while the capability is registered as non-mutating.
    assert policy_action("threat_intel.lookup_ioc", "observe") == "lookup_ioc"
    assert policy_action("threat_intel.lookup_ioc", "investigate") == "lookup_ioc"
    assert policy_action("threat_intel.lookup_ioc", "remediate") == "threat_intel.lookup_ioc"
    # Sharing a last segment with a passive action earns nothing.
    assert policy_action("evil.lookup_ioc", "investigate") == "evil.lookup_ioc"
    assert policy_action("threat_intel.reputation", "investigate") == "threat_intel.reputation"


@pytest.mark.asyncio
async def test_passive_external_lookup_is_allowed_for_the_aliased_capability(h):
    h.receiver.register("threat_intel.lookup_ioc", "investigate", h._lookup)
    status, body = await h.receiver.handle(
        envelope("threat_intel.lookup_ioc", "investigate", target={"scope": "external", "identifier": "8.8.8.8"})
    )
    assert (status, body["status"]) == (200, "completed")
    assert body["decision"]["result"] == "allow_and_notify"


@pytest.mark.asyncio
async def test_a_capability_named_like_a_passive_action_gets_no_allowance(h):
    h.receiver.register("evil.lookup_ioc", "investigate", h._lookup)
    status, body = await h.receiver.handle(
        envelope("evil.lookup_ioc", "investigate", target={"scope": "external", "identifier": "8.8.8.8"})
    )
    assert (status, body["status"]) == (200, "denied")
    assert h.calls == []


# ---- the subject may also be named in the parameters ---------------------------


@pytest.mark.parametrize(
    "parameters",
    [
        {"host": "8.8.8.8"},
        {"ip": "203.0.113.9"},
        {"indicator": "example.com"},
        {"url": "https://example.com/admin"},
        {"URL": "http://8.8.8.8:8080/x"},
        {"hosts": ["192.168.1.5", "8.8.8.8"]},
        {"cidr": "0.0.0.0/0"},
        {"host": 134744072},
    ],
)
def test_external_subject_in_parameters_makes_the_target_external(parameters):
    mapped = policy_target({"scope": "local", "identifier": "192.168.1.20"}, "investigate", parameters)
    assert mapped["is_external"] is True


@pytest.mark.parametrize(
    "parameters",
    [
        {"host": "192.168.1.5"},
        {"url": "http://nas.local:5000/status"},
        {"hosts": ["192.168.1.5", "10.0.0.2"]},
        {"depth": 3, "note": "example.com is mentioned in a comment"},
        {},
        None,
    ],
)
def test_internal_parameters_do_not_make_the_target_external(parameters):
    mapped = policy_target({"scope": "local", "identifier": "192.168.1.20"}, "investigate", parameters)
    assert "is_external" not in mapped


def test_touching_class_without_any_subject_is_external():
    # Nothing says what will be touched, so it cannot be shown to be the owner's.
    assert policy_target({"scope": "local"}, "investigate")["is_external"] is True
    assert policy_target({"scope": "local"}, "remediate", {"depth": 2})["is_external"] is True
    # A device id or an internal subject in the parameters is enough.
    assert "is_external" not in policy_target({"scope": "device", "device_id": "mbp-01"}, "remediate")
    assert "is_external" not in policy_target({"scope": "local"}, "investigate", {"host": "192.168.1.5"})
    # Classes that do not reach into the subject are unaffected.
    assert "is_external" not in policy_target({"scope": "local"}, "contain", {"ip": "203.0.113.9"})


@pytest.mark.asyncio
async def test_gate2_denies_external_host_hidden_in_parameters(h):
    status, body = await h.receiver.handle(
        envelope("network.inspect_host", "investigate", parameters={"host": "8.8.8.8"},
                 authorization_ref="approval:01HAPPROVAL")
    )
    assert (status, body["status"]) == (200, "denied")
    assert body["decision"]["result"] == "deny"
    assert h.calls == []


@pytest.mark.parametrize(
    "parameters",
    [
        {"url": "http://8.8.8.8\\@192.168.1.5/"},          # backslash: parsers disagree on the host
        {"url": "http://192.168.1.5@8.8.8.8/"},
        {"url": "http://user:pw@192.168.1.5/"},              # userinfo is never needed here
        {"url": "http://192.168.1.5\t.example.com/"},
        {"url": "http://192.168.1.5 .example.com/"},
        {"url": "//8.8.8.8/x"},
        {"probe": "8.8.8.8"},                                # an address under any key is a subject
        {"callback": "https://example.com/hook"},            # so is a URL
        {"options": {"host": "8.8.8.8"}},                    # nested
        {"steps": [{"ip": "203.0.113.9"}]},
        {"options": {"deep": {"deeper": {"url": "http://8.8.8.8/"}}}},
    ],
)
def test_disguised_or_nested_external_subjects_are_external(parameters):
    mapped = policy_target({"scope": "local", "identifier": "192.168.1.20"}, "investigate", parameters)
    assert mapped["is_external"] is True


@pytest.mark.parametrize(
    "parameters",
    [
        {"probe": "192.168.1.9"},
        {"callback": "http://nas.local:8080/hook"},
        {"options": {"host": "10.0.0.5", "retries": 3}},
        {"count": 8, "ratio": 0.5, "enabled": True, "label": "weekly"},
    ],
)
def test_internal_values_under_any_key_stay_internal(parameters):
    mapped = policy_target({"scope": "local", "identifier": "192.168.1.20"}, "investigate", parameters)
    assert "is_external" not in mapped


@pytest.mark.parametrize(
    "parameters",
    [
        {"peer": "8.8.8.8:53"},                 # address with a port, under an arbitrary key
        {"upstream": "[2001:4860:4860::8888]:443"},
        {"relay": "203.0.113.9:8080"},
    ],
)
def test_address_with_port_under_any_key_is_a_subject(parameters):
    mapped = policy_target({"scope": "local", "identifier": "192.168.1.20"}, "investigate", parameters)
    assert mapped["is_external"] is True


@pytest.mark.parametrize(
    "parameters",
    [
        {"peer": "192.168.1.9:22"},
        {"upstream": "[fd00::5]:443"},
        {"window": "12:30", "ratio": "3:1", "version": "v1.2", "file": "report.pdf"},
    ],
)
def test_internal_address_with_port_and_ordinary_text_stay_internal(parameters):
    mapped = policy_target({"scope": "local", "identifier": "192.168.1.20"}, "investigate", parameters)
    assert "is_external" not in mapped


def test_host_with_port_under_a_subject_key():
    assert policy_target({"scope": "local"}, "investigate", {"host": "nas.local:5000"}).get("is_external") is None
    assert policy_target({"scope": "local"}, "investigate", {"host": "example.com:443"})["is_external"] is True
    assert policy_target({"scope": "local"}, "investigate", {"host": "192.168.1.5:22"}).get("is_external") is None
