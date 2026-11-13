"""Unit tests for Phase 4 Local Voice Pipeline (tier scaling, zero retention, intent parser, and privilege boundary)."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ecosystem_policy.crypto import Ed25519PolicySigner
from ecosystem_policy.engine import PolicyEngine
from ecosystem_voice import IntentParser, SpeechTranscriber, VoiceIntent, VoiceService
from ecosystem_voice import router as voice_router


def test_transcriber_tier_scaling():
    class DummyHw:
        def __init__(self, t):
            self.tier = t

    t0 = SpeechTranscriber(hardware_info=DummyHw(0))
    assert t0.model_name == "offload"

    t1 = SpeechTranscriber(hardware_info=DummyHw(1))
    assert t1.model_name == "tiny.en"

    t2 = SpeechTranscriber(hardware_info=DummyHw(2))
    assert t2.model_name == "base.en"

    t3 = SpeechTranscriber(hardware_info=DummyHw(3))
    assert t3.model_name == "small.en"


@pytest.mark.asyncio
async def test_transcriber_zero_audio_retention():
    # Provide a bytearray and verify it is scrubbed in-place
    buf = bytearray(b"\x12\x34\x56\x78" * 100)

    def mock_backend(pcm: bytes, rate: int) -> str:
        return "freeze ecosystem"

    transcriber = SpeechTranscriber(mock_backend=mock_backend)
    res = await transcriber.transcribe_pcm(buf)

    assert res == "freeze ecosystem"
    # Ensure buffer bytes were zeroed out
    assert all(b == 0 for b in buf)


def test_intent_parser_allowed_commands():
    parser = IntentParser()

    # Freeze commands
    i1 = parser.parse("please freeze ecosystem")
    assert i1.intent == "ecosystem.freeze"
    assert i1.action == "freeze"

    i2 = parser.parse("emergency freeze")
    assert i2.intent == "ecosystem.freeze"

    # Scan commands
    i3 = parser.parse("scan my workstation", caller_device_id="laptop-1")
    assert i3.intent == "scan.request"
    assert i3.parameters["profile"] == "quick"
    assert i3.target["device_id"] == "laptop-1"

    i4 = parser.parse("run a full scan on this device", caller_device_id="pc-2")
    assert i4.intent == "scan.request"
    assert i4.parameters["profile"] == "full"

    # Scan results
    i5 = parser.parse("show scan results", caller_device_id="laptop-1")
    assert i5.intent == "scan.results"

    # Automation
    i6 = parser.parse("run evening security checks")
    assert i6.intent == "automation.run"


def test_intent_parser_strictly_rejects_privileged_transitions():
    parser = IntentParser()

    # Resume from Freeze attempt
    i1 = parser.parse("resume ecosystem")
    assert i1.is_forbidden()
    assert "ECOSYSTEM_POLICY_FORBIDDEN" in (i1.error or "")

    i2 = parser.parse("unfreeze automations")
    assert i2.is_forbidden()

    # Restrictions: Off attempt
    i3 = parser.parse("turn restrictions off")
    assert i3.is_forbidden()
    assert "step-up authentication" in (i3.error or "")

    # Approval / checkpoint override attempt
    i4 = parser.parse("approve checkpoint")
    assert i4.is_forbidden()

    i5 = parser.parse("deny request")
    assert i5.is_forbidden()


@pytest.mark.asyncio
async def test_voice_service_freeze_execution(tmp_path):
    signer = Ed25519PolicySigner.generate()
    policy = PolicyEngine({}, signer=signer, persistence_path=tmp_path / "policy.json")

    service = VoiceService(policy_engine=policy)

    assert policy.frozen is False
    res = await service.handle_text_utterance("freeze ecosystem", caller_id="operator_mic")

    assert res["success"] is True
    assert res["frozen"] is True
    assert policy.frozen is True
    assert "Emergency freeze engaged" in res["spoken_response"]


def test_voice_api_endpoints(tmp_path):
    signer = Ed25519PolicySigner.generate()
    policy = PolicyEngine({}, signer=signer, persistence_path=tmp_path / "policy.json")

    service = VoiceService(policy_engine=policy)

    app = FastAPI()
    app.state.voice_service = service
    app.include_router(voice_router)

    client = TestClient(app)

    # 1. GET /voice/status
    r = client.get("/voice/status")
    assert r.status_code == 200
    assert r.json()["zero_retention"] is True

    # 2. POST /voice/intent with freeze
    r = client.post("/voice/intent", json={"text": "freeze automations", "caller_id": "hallway_mic"})
    assert r.status_code == 200
    assert r.json()["frozen"] is True
    assert policy.frozen is True

    # 3. POST /voice/intent with forbidden resume command -> 403 Forbidden
    r = client.post("/voice/intent", json={"text": "resume operations", "caller_id": "hallway_mic"})
    assert r.status_code == 403
    assert "ECOSYSTEM_POLICY_FORBIDDEN" in r.json()["detail"]

