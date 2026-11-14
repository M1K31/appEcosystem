"""Adapters that mount a CommandReceiver on non-FastAPI apps (WP1b Task 1)."""
from __future__ import annotations

import asyncio
import threading

import pytest

from ecosystem_hub import CommandReceiver
from ecosystem_hub.command_adapters import (
    build_aiohttp_handler,
    build_flask_view,
    build_receiver_from_env,
)
from ecosystem_client.contracts import build_command_envelope
from ecosystem_policy import PolicyEngine

SECRET = "adapter-test-secret-0123456789abcdef"
ACTOR = {"id": "x", "type": "service", "app": "ai_for_survival", "device_id": "local-device"}


def _receiver(tmp_path, *, handler=None, name="aegissiem"):
    engine = PolicyEngine(authority="hub_synced")
    rec = CommandReceiver(name, secret=SECRET, policy_engine=engine, replay_db_path=tmp_path / f"{name}.db")

    async def ok(ctx):
        return {"ran": ctx.command, "subject": ctx.target.get("identifier")}

    rec.register("threat_intel.lookup_ioc", "observe", handler or ok)
    return rec


def _envelope(command="threat_intel.lookup_ioc", action_class="observe", key="k-1", **kw):
    return build_command_envelope(
        command, action_class, ACTOR, {"scope": "local", "identifier": "192.168.1.20"}, SECRET,
        parameters={"indicator": "192.168.1.20"}, idempotency_key=key, **kw,
    )


# ---- aiohttp -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_aiohttp_handler_round_trip(tmp_path):
    from aiohttp import web
    from aiohttp.test_utils import TestClient, TestServer

    rec = _receiver(tmp_path)
    app = web.Application()
    app.router.add_post("/ecosystem/commands", build_aiohttp_handler(rec))

    async with TestClient(TestServer(app)) as client:
        ok = await client.post("/ecosystem/commands", json=_envelope())
        assert ok.status == 200
        body = await ok.json()
        assert body["status"] == "completed"
        assert body["result"] == {"ran": "threat_intel.lookup_ioc", "subject": "192.168.1.20"}

        env = _envelope(key="k-2")
        del env["signature"]
        bad = await client.post("/ecosystem/commands", json=env)
        assert bad.status == 401

        garbage = await client.post("/ecosystem/commands", data=b"{not json",
                                    headers={"content-type": "application/json"})
        assert garbage.status == 401


# ---- Flask ---------------------------------------------------------------------


class _Loop:
    """A background asyncio loop thread, as a Flask app runs the receiver on."""

    def __enter__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        return self.loop

    def __exit__(self, *exc):
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(timeout=5)
        self.loop.close()


def test_flask_view_round_trip(tmp_path):
    from flask import Flask

    with _Loop() as loop:
        rec = _receiver(tmp_path)
        app = Flask(__name__)
        app.add_url_rule("/ecosystem/commands", "cmd", build_flask_view(rec, loop), methods=["POST"])
        client = app.test_client()

        ok = client.post("/ecosystem/commands", json=_envelope())
        assert ok.status_code == 200
        assert ok.get_json()["status"] == "completed"

        env = _envelope(key="k-2")
        del env["signature"]
        assert client.post("/ecosystem/commands", json=env).status_code == 401

        assert client.post("/ecosystem/commands", data=b"{bad", content_type="application/json").status_code == 401


def test_flask_view_timeout_is_outcome_unknown(tmp_path):
    from flask import Flask

    async def hang(ctx):
        await asyncio.sleep(5)

    with _Loop() as loop:
        rec = _receiver(tmp_path)
        rec.register("camera.snapshot", "observe", hang)
        app = Flask(__name__)
        app.add_url_rule("/ecosystem/commands", "cmd", build_flask_view(rec, loop, timeout=0.2), methods=["POST"])
        client = app.test_client()

        resp = client.post("/ecosystem/commands", json=_envelope("camera.snapshot", key="hang-1"))
        assert resp.status_code == 504
        body = resp.get_json()
        assert body["status"] == "failed"
        assert body["outcome_unknown"] is True


# ---- build_receiver_from_env ---------------------------------------------------


def test_build_receiver_without_secret_returns_none(tmp_path, monkeypatch):
    monkeypatch.delenv("ECOSYSTEM_HMAC_SECRET", raising=False)
    monkeypatch.setenv("ECOSYSTEM_SECRET_FILE", str(tmp_path / "absent.env"))
    engine = PolicyEngine(authority="hub_synced")
    assert build_receiver_from_env("aegissiem", policy_engine=engine, replay_db_path=tmp_path / "r.db") is None


def test_build_receiver_wires_both_verifiers(tmp_path):
    from ecosystem_hub.command_receiver import HubApprovalVerifier

    engine = PolicyEngine(authority="hub_synced")
    rec = build_receiver_from_env(
        "aegissiem", policy_engine=engine, replay_db_path=tmp_path / "r.db",
        registry_url="http://hub.test:8500", secret=SECRET,
    )
    assert isinstance(rec, CommandReceiver)
    assert isinstance(rec._verifier, HubApprovalVerifier)
    assert rec._verifier.app_name == "aegissiem"
    # The context verifier is the same hub check, bound to confirm_context.
    assert getattr(rec._context_verifier, "__self__", None) is rec._verifier
    assert rec._context_verifier == rec._verifier.confirm_context


def test_build_receiver_reads_the_secret_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", SECRET)
    engine = PolicyEngine(authority="hub_synced")
    rec = build_receiver_from_env("openeye", policy_engine=engine, replay_db_path=tmp_path / "r.db")
    assert isinstance(rec, CommandReceiver)
    assert rec.app_name == "openeye"
