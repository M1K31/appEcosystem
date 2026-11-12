"""Hub-side record of dispatched commands: idempotency, immutability, audit trail."""
from __future__ import annotations

import json

import pytest

from ecosystem_hub.command_common import (
    MAX_JSON_BYTES,
    json_too_large,
    request_digest,
)
from ecosystem_hub.command_store import CommandStore, IdempotencyConflict


@pytest.fixture
def store(tmp_path):
    return CommandStore(tmp_path / "commands.db")


def _create(store, *, command_id="01HZZZZZZZZZZZZZZZZZZZZZZ1", requester="aegissiem", key="k-1",
            parameters=None, now=1000.0):
    target = {"scope": "local", "identifier": "192.168.1.20"}
    params = {"ip": "192.168.1.20"} if parameters is None else parameters
    return store.create(
        command_id=command_id,
        requester_app=requester,
        idempotency_key=key,
        capability="containment.block_ip",
        action_class="contain",
        actor={"id": "aegissiem", "type": "service", "app": requester, "device_id": "local-device"},
        target=target,
        parameters=params,
        rationale="repeated failed logins",
        correlation_id="corr-1",
        digest=request_digest("containment.block_ip", target, params),
        now=now,
    )


def test_create_then_duplicate_key_returns_first_record(store):
    first, created = _create(store)
    assert created is True
    assert first["status"] == "received"
    again, created_again = _create(store, command_id="01HZZZZZZZZZZZZZZZZZZZZZZ2")
    assert created_again is False
    assert again["command_id"] == first["command_id"]


def test_same_key_different_digest_conflicts(store):
    _create(store)
    with pytest.raises(IdempotencyConflict):
        _create(store, command_id="01HZZZZZZZZZZZZZZZZZZZZZZ2", parameters={"ip": "192.168.1.99"})


def test_same_key_from_another_requester_is_independent(store):
    first, _ = _create(store)
    other, created = _create(store, command_id="01HZZZZZZZZZZZZZZZZZZZZZZ2", requester="ai_for_survival")
    assert created is True
    assert other["command_id"] != first["command_id"]


def test_update_appends_audit_event_in_order(store):
    rec, _ = _create(store)
    store.update(rec["command_id"], decision={"result": "allow"}, event="decided", now=1001.0)
    store.update(rec["command_id"], status="dispatching", provider_app="aegissiem",
                 event="forwarded", detail={"url": "http://localhost:8089/ecosystem/commands"}, now=1002.0)
    got = store.get(rec["command_id"])
    assert [e["event"] for e in got["events"]] == ["created", "decided", "forwarded"]
    assert got["events"][2]["detail"] == {"url": "http://localhost:8089/ecosystem/commands"}
    assert got["decision"] == {"result": "allow"}
    assert got["provider_app"] == "aegissiem"
    assert got["updated_at"] == 1002.0


def test_final_status_is_immutable(store):
    rec, _ = _create(store)
    store.update(rec["command_id"], status="completed", result={"blocked": True}, event="completed")
    with pytest.raises(ValueError):
        store.update(rec["command_id"], status="failed", error="late")
    assert store.get(rec["command_id"])["status"] == "completed"


def test_claim_is_atomic(store):
    rec, _ = _create(store)
    assert store.claim(rec["command_id"], from_status="received") is True
    assert store.claim(rec["command_id"], from_status="received") is False
    assert store.get(rec["command_id"])["status"] == "dispatching"


def test_recover_interrupted_marks_outcome_unknown(store):
    rec, _ = _create(store)
    store.claim(rec["command_id"], from_status="received")
    assert store.recover_interrupted(now=2000.0) == 1
    got = store.get(rec["command_id"])
    assert got["status"] == "failed"
    assert got["outcome_unknown"] is True
    assert got["events"][-1]["event"] == "interrupted_by_restart"
    assert store.recover_interrupted() == 0


def test_reopen_unknown_only_reopens_unknown_outcomes(store):
    rec, _ = _create(store)
    store.update(rec["command_id"], status="failed", error="timeout", outcome_unknown=True)
    assert store.reopen_unknown(rec["command_id"]) is True
    assert store.get(rec["command_id"])["status"] == "dispatching"

    other, _ = _create(store, command_id="01HZZZZZZZZZZZZZZZZZZZZZZ2", key="k-2")
    store.update(other["command_id"], status="failed", error="router rejected rule")
    assert store.reopen_unknown(other["command_id"]) is False
    assert store.get(other["command_id"])["status"] == "failed"


def test_get_by_approval(store):
    rec, _ = _create(store)
    store.update(rec["command_id"], status="pending_approval", approval_id="APPROVAL1")
    assert store.get_by_approval("APPROVAL1")["command_id"] == rec["command_id"]
    assert store.get_by_approval("missing") is None


def test_list_filters_by_correlation_and_status(store):
    a, _ = _create(store)
    _create(store, command_id="01HZZZZZZZZZZZZZZZZZZZZZZ2", key="k-2")
    store.update(a["command_id"], status="completed")
    assert len(store.list(correlation_id="corr-1")) == 2
    assert [r["command_id"] for r in store.list(status="completed")] == [a["command_id"]]
    assert store.list(correlation_id="other") == []


def test_request_digest_ignores_key_order():
    a = request_digest("x.y", {"scope": "local", "identifier": "a"}, {"p": 1, "q": 2})
    b = request_digest("x.y", {"identifier": "a", "scope": "local"}, {"q": 2, "p": 1})
    assert a == b
    assert len(a) == 64
    assert a != request_digest("x.y", {"scope": "local", "identifier": "a"}, {"p": 1, "q": 3})


def test_json_too_large_at_64_kib():
    assert MAX_JSON_BYTES == 65_536
    overhead = len(json.dumps({"v": ""}, separators=(",", ":")).encode())
    assert json_too_large({"v": "x" * (65_536 - overhead)}) is False
    assert json_too_large({"v": "x" * (65_537 - overhead)}) is True
