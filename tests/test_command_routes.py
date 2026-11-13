"""HTTP surface of command dispatch on the hub: /commands/*."""
from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from ecosystem_auth.tokens import sign_request
from ecosystem_hub import CommandStore
from ecosystem_hub.command_common import request_digest
from registry.models import ServiceRegistration
from tests.test_command_dispatch import SECRET, Provider, manifest

LOCAL = {"scope": "local", "identifier": "192.168.1.20"}


def _env(monkeypatch, tmp_path):
    monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", SECRET)
    monkeypatch.setenv("ECOSYSTEM_CONFIG", str(tmp_path / "missing.yaml"))
    monkeypatch.setenv("ECOSYSTEM_APPS_FILE", str(tmp_path / "apps.json"))
    monkeypatch.setenv("ECOSYSTEM_REGISTRY_FILE", str(tmp_path / "registry.json"))
    monkeypatch.setenv("ECOSYSTEM_CAPABILITIES_FILE", str(tmp_path / "caps.json"))
    monkeypatch.setenv("ECOSYSTEM_NOTIFICATIONS_DB", str(tmp_path / "notify.db"))
    monkeypatch.setenv("ECOSYSTEM_AI_PROFILE_FILE", str(tmp_path / "ai_profile.json"))
    monkeypatch.setenv("ECOSYSTEM_POLICY_KEY_DIR", str(tmp_path / "pkeys"))
    monkeypatch.setenv("ECOSYSTEM_POLICY_STATE_FILE", str(tmp_path / "pstate.json"))
    monkeypatch.setenv("ECOSYSTEM_STEP_UP_FILE", str(tmp_path / "step_up.json"))
    monkeypatch.setenv("ECOSYSTEM_APPROVALS_DB", str(tmp_path / "approvals.db"))
    monkeypatch.setenv("ECOSYSTEM_COMMANDS_DB", str(tmp_path / "commands.db"))


class Hub:
    def __init__(self, client, tmp_path):
        self.client = client
        self.state = client.app.state
        self.tmp_path = tmp_path
        self.providers: dict[str, Provider] = {}
        self.state.command_dispatcher._client_factory = self._provider_client

    def _provider_client(self):
        return httpx.AsyncClient(
            mounts={f"all://{n}.test": httpx.ASGITransport(app=p.app) for n, p in self.providers.items()}
        )

    def add_provider(self, name, capability, action_class="observe", *, port=8089, **manifest_extra):
        provider = self.providers.get(name) or Provider(name, self.tmp_path)
        self.providers[name] = provider
        provider.offer(capability, action_class)
        self.state.capability_registry.register(manifest(capability, name, action_class, **manifest_extra))
        self.state.registry.register(ServiceRegistration(name=name, host=f"{name}.test", port=port))
        return provider

    def register_service(self, name, port=8000):
        self.state.registry.register(ServiceRegistration(name=name, host=f"{name}.test", port=port))

    def body(self, capability="threat_intel.lookup_ioc", **over):
        doc = {
            "capability": capability,
            "target": dict(LOCAL),
            "parameters": {"indicator": "192.168.1.20"},
            "actor": {"app": "ai_for_survival", "id": "blue-team", "type": "service"},
            "rationale": "test",
            "idempotency_key": "key-1",
        }
        doc.update(over)
        return doc

    def dispatch(self, body, *, secret=SECRET, key_id=None, sign=True):
        headers = sign_request("POST", "/commands/dispatch", secret, body=body, key_id=key_id) if sign else {}
        return self.client.post("/commands/dispatch", json=body, headers=headers)


@pytest.fixture
def hub(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path)
    from registry.app import app

    with TestClient(app) as client:
        h = Hub(client, tmp_path)
        h.register_service("ai_for_survival")
        yield h


def test_unsigned_dispatch_is_rejected_even_from_loopback(hub):
    provider = hub.add_provider("aegissiem", "threat_intel.lookup_ioc")
    resp = hub.dispatch(hub.body(), sign=False)
    assert resp.status_code == 401
    assert provider.envelopes == []


def test_dispatch_returns_status_document(hub):
    provider = hub.add_provider("aegissiem", "threat_intel.lookup_ioc")
    resp = hub.dispatch(hub.body())
    assert resp.status_code == 200
    doc = resp.json()
    assert set(doc) == {
        "command_id", "status", "capability", "provider", "decision", "approval_id", "result", "error",
        "outcome_unknown", "correlation_id",
    }
    assert doc["status"] == "completed"
    assert doc["provider"] == "aegissiem"
    sent = provider.envelopes[0]
    assert sent["actor"] == {
        "id": "blue-team", "type": "service", "app": "ai_for_survival", "device_id": "local-device",
        "auth_method": None,
    }


def test_actor_defaults(hub):
    provider = hub.add_provider("aegissiem", "threat_intel.lookup_ioc")
    resp = hub.dispatch(hub.body(actor={"app": "ai_for_survival"}))
    assert resp.status_code == 200
    assert provider.envelopes[0]["actor"]["id"] == "ai_for_survival"
    assert provider.envelopes[0]["actor"]["type"] == "service"


def test_shared_secret_caller_must_name_a_registered_service(hub):
    hub.add_provider("aegissiem", "threat_intel.lookup_ioc")
    resp = hub.dispatch(hub.body(actor={"app": "nonexistent"}))
    assert resp.status_code == 422
    assert hub.dispatch(hub.body(actor={})).status_code == 422
    body = hub.body()
    del body["actor"]
    assert hub.dispatch(body).status_code == 422


def test_shared_secret_identity_is_marked_in_the_audit_trail(hub):
    hub.add_provider("aegissiem", "threat_intel.lookup_ioc")
    doc = hub.dispatch(hub.body()).json()
    record = hub.client.get(f"/commands/{doc['command_id']}").json()
    assert record["events"][0]["event"] == "created"
    assert record["events"][0]["detail"]["identity"] == "shared_secret"


def _enrol(hub, app_id, owned, scopes):
    public, secret = hub.state.app_store.add(app_id, app_id, "tester", owned, scopes=scopes)
    for name in owned:
        hub.register_service(name, port=9100)
    return public["key_id"], secret


def test_app_key_caller_needs_the_dispatch_scope(hub):
    hub.add_provider("aegissiem", "threat_intel.lookup_ioc")
    key_id, secret = _enrol(hub, "partner", ["partner_svc"], ["register:self"])
    resp = hub.dispatch(hub.body(actor={"app": "partner_svc"}), secret=secret, key_id=key_id)
    assert resp.status_code == 403


def test_app_key_caller_cannot_act_as_another_app(hub):
    provider = hub.add_provider("aegissiem", "threat_intel.lookup_ioc")
    key_id, secret = _enrol(hub, "partner", ["partner_svc"], ["register:self", "commands:dispatch"])
    forged = hub.dispatch(hub.body(actor={"app": "ai_for_survival"}), secret=secret, key_id=key_id)
    assert forged.status_code == 403
    assert provider.envelopes == []
    own = hub.dispatch(hub.body(actor={"app": "partner_svc"}), secret=secret, key_id=key_id)
    assert own.status_code == 200
    record = hub.client.get(f"/commands/{own.json()['command_id']}").json()
    assert record["events"][0]["detail"]["identity"] == "app_key"
    assert record["requester_app"] == "partner_svc"


def test_operator_actor_requires_step_up(hub):
    provider = hub.add_provider("aegissiem", "threat_intel.lookup_ioc")
    operator = {"app": "ai_for_survival", "id": "someone", "type": "operator"}
    refused = hub.dispatch(hub.body(actor=operator))
    assert refused.status_code == 403
    assert provider.envelopes == []

    token = hub.state.step_up_auth.issue_step_up_token("admin", auth_method="totp")["step_up_token"]
    ok = hub.dispatch(hub.body(actor=operator, step_up_token=token))
    assert ok.status_code == 200
    actor = provider.envelopes[0]["actor"]
    # The operator is who the step-up says, not who the body says.
    assert (actor["type"], actor["id"], actor["auth_method"]) == ("operator", "admin", "totp")


@pytest.mark.parametrize(
    "change",
    [
        {"capability": ""},
        {"capability": "Not A Capability"},
        {"target": {}},
        {"target": {"scope": "galaxy"}},
        {"target": {"scope": "local", "unexpected": 1}},
        {"target": "192.168.1.20"},
        {"parameters": ["a", "b"]},
        {"idempotency_key": ""},
        {"idempotency_key": "k" * 200},
        {"actor": {"app": "ai_for_survival", "type": "superuser"}},
        {"rationale": "x" * 5000},
        {"context": "schedule"},
    ],
)
def test_malformed_requests_are_422_and_not_stored(hub, change):
    hub.add_provider("aegissiem", "threat_intel.lookup_ioc")
    resp = hub.dispatch(hub.body(**change))
    assert resp.status_code == 422
    assert hub.client.get("/commands").json()["commands"] == []


def test_invalid_parameters_are_422_and_not_stored(hub):
    provider = hub.add_provider(
        "aegissiem", "threat_intel.lookup_ioc",
        inputs_schema={
            "type": "object",
            "required": ["indicator"],
            "properties": {"indicator": {"type": "string"}},
            "additionalProperties": False,
        },
    )
    assert hub.dispatch(hub.body(parameters={"indicator": 42})).status_code == 422
    assert hub.dispatch(hub.body(parameters={"indicator": "x", "extra": True})).status_code == 422
    assert hub.dispatch(hub.body(parameters={})).status_code == 422
    assert hub.client.get("/commands").json()["commands"] == []
    assert provider.envelopes == []
    assert hub.dispatch(hub.body()).status_code == 200


def test_oversized_parameters_are_422(hub):
    hub.add_provider("aegissiem", "threat_intel.lookup_ioc")
    resp = hub.dispatch(hub.body(parameters={"indicator": "x" * 70_000}))
    assert resp.status_code == 422


def test_idempotency_conflict_is_409(hub):
    provider = hub.add_provider("aegissiem", "threat_intel.lookup_ioc")
    assert hub.dispatch(hub.body()).status_code == 200
    assert hub.dispatch(hub.body(parameters={"indicator": "192.168.1.99"})).status_code == 409
    assert len(provider.calls) == 1


def test_duplicate_request_returns_the_same_command(hub):
    provider = hub.add_provider("aegissiem", "threat_intel.lookup_ioc")
    a = hub.dispatch(hub.body()).json()
    b = hub.dispatch(hub.body()).json()
    assert a["command_id"] == b["command_id"]
    assert len(provider.calls) == 1


def test_get_command_includes_events_and_approval(hub):
    hub.add_provider("aegissiem", "network.inspect_host", "investigate")
    doc = hub.dispatch(hub.body("network.inspect_host", parameters={"host": "192.168.1.20"})).json()
    assert doc["status"] == "pending_approval"
    record = hub.client.get(f"/commands/{doc['command_id']}").json()
    assert record["status"] == "pending_approval"
    assert record["provider"] == "aegissiem"
    assert record["capability"] == "network.inspect_host"
    assert record["action_class"] == "investigate"
    assert record["requester_app"] == "ai_for_survival"
    assert record["digest"] == request_digest("network.inspect_host", LOCAL, {"host": "192.168.1.20"})
    assert record["approval_id"] == doc["approval_id"]
    assert record["approval"]["status"] == "pending"
    assert record["approval"]["target"]["command_id"] == doc["command_id"]
    assert [e["event"] for e in record["events"]][:2] == ["created", "decided"]
    assert hub.client.get("/commands/01HZZZZZZZZZZZZZZZZZZZZZZZ").status_code == 404


def test_list_by_correlation_id(hub):
    hub.add_provider("aegissiem", "threat_intel.lookup_ioc")
    hub.dispatch(hub.body(correlation_id="incident-7"))
    hub.dispatch(hub.body(idempotency_key="key-2", correlation_id="incident-7"))
    hub.dispatch(hub.body(idempotency_key="key-3", correlation_id="other"))
    listed = hub.client.get("/commands", params={"correlation_id": "incident-7"}).json()["commands"]
    assert len(listed) == 2
    assert {c["correlation_id"] for c in listed} == {"incident-7"}
    assert len(hub.client.get("/commands", params={"status": "completed"}).json()["commands"]) == 3


def _accepted_command(hub):
    from ecosystem_hub import Accepted

    provider = hub.add_provider("openeye", "camera.record_clip", port=8200)

    async def start(ctx):
        return Accepted("job-42")

    provider.receiver.register("camera.record_clip", "observe", start)
    doc = hub.dispatch(hub.body("camera.record_clip", target={"scope": "local"}, parameters={})).json()
    assert doc["status"] == "accepted"
    return doc["command_id"]


def _post_result(hub, command_id, body, *, secret=SECRET, key_id=None):
    path = f"/commands/{command_id}/result"
    return hub.client.post(path, json=body, headers=sign_request("POST", path, secret, body=body, key_id=key_id))


def test_result_callback_completes_an_accepted_command_once(hub):
    cid = _accepted_command(hub)
    first = _post_result(hub, cid, {"status": "completed", "result": {"clip": "clip-42.mp4"}})
    assert first.status_code == 200
    assert first.json()["status"] == "completed"
    assert first.json()["result"] == {"clip": "clip-42.mp4"}
    second = _post_result(hub, cid, {"status": "failed", "error": "late"})
    assert second.status_code == 409
    assert hub.client.get(f"/commands/{cid}").json()["status"] == "completed"


def test_result_callback_rejects_bad_input(hub):
    cid = _accepted_command(hub)
    assert _post_result(hub, cid, {"status": "accepted"}).status_code == 422
    assert _post_result(hub, cid, {"status": "completed", "result": {"blob": "x" * 70_000}}).status_code == 422
    assert _post_result(hub, "01HZZZZZZZZZZZZZZZZZZZZZZZ", {"status": "completed"}).status_code == 404
    unsigned = hub.client.post(f"/commands/{cid}/result", json={"status": "completed"})
    assert unsigned.status_code == 401


def test_result_callback_from_non_provider_is_403(hub):
    cid = _accepted_command(hub)
    key_id, secret = _enrol(hub, "partner", ["partner_svc"], ["register:self", "commands:dispatch"])
    resp = _post_result(hub, cid, {"status": "completed", "result": {}}, secret=secret, key_id=key_id)
    assert resp.status_code == 403
    assert hub.client.get(f"/commands/{cid}").json()["status"] == "accepted"


def test_interrupted_commands_are_recovered_on_startup(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path)
    store = CommandStore(tmp_path / "commands.db")
    target, params = {"scope": "local"}, {}
    rec, _ = store.create(
        command_id="01HZZZZZZZZZZZZZZZZZZZZZZ1", requester_app="ai_for_survival", idempotency_key="k",
        capability="containment.block_ip", action_class="contain",
        actor={"id": "a", "type": "service", "app": "ai_for_survival", "device_id": "local-device"},
        target=target, parameters=params, rationale=None, correlation_id="c",
        digest=request_digest("containment.block_ip", target, params),
    )
    store.claim(rec["command_id"], from_status="received")

    from registry.app import app

    with TestClient(app) as client:
        record = client.get(f"/commands/{rec['command_id']}").json()
        assert record["status"] == "failed"
        assert record["outcome_unknown"] is True
        assert record["events"][-1]["event"] == "interrupted_by_restart"


def test_commands_are_readable_from_loopback_without_a_signature(hub):
    hub.add_provider("aegissiem", "threat_intel.lookup_ioc")
    hub.dispatch(hub.body())
    assert hub.client.get("/commands").status_code == 200
    remote = hub.client.get("/commands", headers={"x-forwarded-for": "203.0.113.5"})
    assert remote.status_code == 401


# ---- who may read command records ---------------------------------------------


def _get(hub, path, *, secret, key_id):
    return hub.client.get(path, headers=sign_request("GET", path, secret, key_id=key_id))


def test_app_key_caller_reads_only_its_own_commands(hub):
    hub.add_provider("aegissiem", "threat_intel.lookup_ioc")
    theirs = hub.dispatch(hub.body()).json()["command_id"]  # a first-party command
    key_id, secret = _enrol(hub, "partner", ["partner_svc"], ["commands:dispatch", "commands:read"])
    mine = hub.dispatch(
        hub.body(actor={"app": "partner_svc"}, idempotency_key="p-1"), secret=secret, key_id=key_id
    ).json()["command_id"]

    assert _get(hub, f"/commands/{mine}", secret=secret, key_id=key_id).status_code == 200
    # Someone else's record looks exactly like one that does not exist.
    assert _get(hub, f"/commands/{theirs}", secret=secret, key_id=key_id).status_code == 404
    listed = _get(hub, "/commands", secret=secret, key_id=key_id).json()["commands"]
    assert [c["command_id"] for c in listed] == [mine]


def test_app_key_caller_needs_a_read_scope(hub):
    hub.add_provider("aegissiem", "threat_intel.lookup_ioc")
    key_id, secret = _enrol(hub, "partner", ["partner_svc"], ["commands:dispatch"])
    mine = hub.dispatch(
        hub.body(actor={"app": "partner_svc"}, idempotency_key="p-1"), secret=secret, key_id=key_id
    ).json()["command_id"]
    assert _get(hub, f"/commands/{mine}", secret=secret, key_id=key_id).status_code == 403
    assert _get(hub, "/commands", secret=secret, key_id=key_id).status_code == 403


def test_owner_reads_every_command(hub):
    hub.add_provider("aegissiem", "threat_intel.lookup_ioc")
    cid = hub.dispatch(hub.body()).json()["command_id"]
    path = f"/commands/{cid}"
    assert hub.client.get(path, headers=sign_request("GET", path, SECRET)).status_code == 200
