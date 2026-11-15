"""HubRuntime.invoke: an app asks the hub to run a capability."""
from __future__ import annotations

import json

import httpx
import pytest
from fastapi import FastAPI, HTTPException, Request

from ecosystem_auth.tokens import verify_request
from ecosystem_client.config import EcosystemConfig
from ecosystem_client.ulid import is_ulid
from ecosystem_hub import HubRole, HubRuntime

SECRET = "invoke-test-secret-0123456789abcdef"


class FakeHub:
    def __init__(self):
        self.requests: list[dict] = []
        self.answer = {"command_id": "01HZZZZZZZZZZZZZZZZZZZZZZ1", "status": "completed", "result": {"ok": True}}
        self.fail_with: tuple[int, str] | None = None
        self.app = FastAPI()

        @self.app.post("/commands/dispatch")
        async def dispatch(request: Request):
            body = json.loads(await request.body())
            signed = verify_request(
                "POST", str(request.url), SECRET,
                request.headers.get("X-Ecosystem-Signature", ""),
                request.headers.get("X-Ecosystem-Timestamp", ""),
                request.headers.get("X-Ecosystem-Nonce", ""),
                body,
            )
            self.requests.append({"body": body, "signed": signed})
            if self.fail_with:
                raise HTTPException(status_code=self.fail_with[0], detail=self.fail_with[1])
            return self.answer

        @self.app.get("/commands/{command_id}")
        async def get_command(command_id: str):
            if command_id != self.answer["command_id"]:
                raise HTTPException(status_code=404, detail="not found")
            return {**self.answer, "events": []}


def runtime(tmp_path, hub: FakeHub | None, *, secret=SECRET) -> HubRuntime:
    rt = HubRuntime(
        "ai_for_survival",
        role=HubRole.OFF,
        config=EcosystemConfig(registry_url="http://hub.test:8500", hmac_secret=secret),
        lock_path=tmp_path / "hub.lock",
        outbox_path=tmp_path / "outbox.db",
    )
    if hub is not None:
        rt._http_factory = lambda timeout: httpx.AsyncClient(
            transport=httpx.ASGITransport(app=hub.app), timeout=timeout
        )
    return rt


@pytest.mark.asyncio
async def test_invoke_posts_signed_request_and_returns_status(tmp_path):
    hub = FakeHub()
    rt = runtime(tmp_path, hub)
    out = await rt.invoke(
        "threat_intel.lookup_ioc",
        {"scope": "local", "identifier": "192.168.1.20"},
        {"indicator": "192.168.1.20"},
        rationale="unusual traffic",
        correlation_id="incident-7",
        context={"trigger": "schedule"},
    )
    assert out == hub.answer
    sent = hub.requests[0]
    assert sent["signed"] is True
    body = sent["body"]
    assert body["capability"] == "threat_intel.lookup_ioc"
    assert body["target"] == {"scope": "local", "identifier": "192.168.1.20"}
    assert body["parameters"] == {"indicator": "192.168.1.20"}
    assert body["actor"] == {"app": "ai_for_survival", "id": "ai_for_survival", "type": "service",
                             "device_id": rt.device_id}
    assert body["rationale"] == "unusual traffic"
    assert body["correlation_id"] == "incident-7"
    assert body["context"] == {"trigger": "schedule"}
    assert "step_up_token" not in body


@pytest.mark.asyncio
async def test_invoke_generates_idempotency_key(tmp_path):
    hub = FakeHub()
    rt = runtime(tmp_path, hub)
    await rt.invoke("threat_intel.lookup_ioc", {"scope": "local"})
    await rt.invoke("threat_intel.lookup_ioc", {"scope": "local"})
    keys = [r["body"]["idempotency_key"] for r in hub.requests]
    assert all(is_ulid(k) for k in keys)
    assert keys[0] != keys[1]
    assert hub.requests[0]["body"]["parameters"] == {}


@pytest.mark.asyncio
async def test_invoke_reuses_given_idempotency_key(tmp_path):
    hub = FakeHub()
    rt = runtime(tmp_path, hub)
    await rt.invoke("threat_intel.lookup_ioc", {"scope": "local"}, idempotency_key="retry-me")
    assert hub.requests[0]["body"]["idempotency_key"] == "retry-me"


@pytest.mark.asyncio
async def test_invoke_as_operator_sends_the_step_up_token(tmp_path):
    hub = FakeHub()
    rt = runtime(tmp_path, hub)
    await rt.invoke("containment.block_ip", {"scope": "local"}, actor_type="operator", actor_id="mikel",
                    step_up_token="tok-123")
    body = hub.requests[0]["body"]
    assert body["actor"]["type"] == "operator"
    assert body["actor"]["id"] == "mikel"
    assert body["step_up_token"] == "tok-123"


@pytest.mark.asyncio
async def test_invoke_when_hub_unreachable_queues_nothing(tmp_path):
    rt = runtime(tmp_path, None)  # real transport: the suite's network guard refuses the connection
    before = rt.outbox.pending_count() if hasattr(rt.outbox, "pending_count") else None
    out = await rt.invoke("containment.block_ip", {"scope": "local", "identifier": "203.0.113.9"})
    assert out == {"status": "provider_unavailable", "error": "hub_unreachable", "command_id": None}
    if before is not None:
        assert rt.outbox.pending_count() == before


@pytest.mark.asyncio
async def test_invoke_without_secret_is_not_configured(tmp_path):
    hub = FakeHub()
    rt = runtime(tmp_path, hub, secret="")
    out = await rt.invoke("threat_intel.lookup_ioc", {"scope": "local"})
    assert out == {"status": "provider_unavailable", "error": "not_configured", "command_id": None}
    assert hub.requests == []


@pytest.mark.asyncio
async def test_invoke_surfaces_hub_4xx(tmp_path):
    hub = FakeHub()
    hub.fail_with = (409, "idempotency_key 'k' was already used for a different request")
    rt = runtime(tmp_path, hub)
    out = await rt.invoke("threat_intel.lookup_ioc", {"scope": "local"}, idempotency_key="k")
    assert out["status"] == "failed"
    assert out["http_status"] == 409
    assert "already used" in out["error"]
    assert out["command_id"] is None


@pytest.mark.asyncio
async def test_invoke_reports_a_hub_5xx_as_unknown_outcome(tmp_path):
    hub = FakeHub()
    hub.fail_with = (500, "boom")
    rt = runtime(tmp_path, hub)
    out = await rt.invoke("containment.block_ip", {"scope": "local"}, idempotency_key="k")
    assert out["status"] == "failed"
    assert out["http_status"] == 500
    assert out["outcome_unknown"] is True


@pytest.mark.asyncio
async def test_get_command(tmp_path):
    hub = FakeHub()
    rt = runtime(tmp_path, hub)
    assert (await rt.get_command("01HZZZZZZZZZZZZZZZZZZZZZZ1"))["status"] == "completed"
    assert await rt.get_command("01HZZZZZZZZZZZZZZZZZZZZZZ9") is None
