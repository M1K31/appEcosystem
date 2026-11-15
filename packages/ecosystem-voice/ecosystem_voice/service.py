"""Voice service endpoints and policy integration."""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status

from .intents import IntentParser, VoiceIntent
from .transcriber import SpeechTranscriber

logger = logging.getLogger("ecosystem.voice.service")


class VoiceService:
    """Orchestrates local speech transcription, intent parsing, policy gating, and execution."""

    def __init__(
        self,
        transcriber: Optional[SpeechTranscriber] = None,
        parser: Optional[IntentParser] = None,
        policy_engine: Any = None,
        event_bus: Any = None,
        scan_runner: Any = None,
    ):
        self.transcriber = transcriber or SpeechTranscriber()
        self.parser = parser or IntentParser()
        self.policy_engine = policy_engine
        self.event_bus = event_bus
        self.scan_runner = scan_runner

    async def execute_intent(
        self,
        intent: VoiceIntent,
        *,
        caller_id: str = "voice_operator",
        caller_device_id: str = "local",
    ) -> dict[str, Any]:
        """Execute a structured voice intent against PolicyEngine and ecosystem capabilities."""
        if intent.is_forbidden():
            return {
                "success": False,
                "error": intent.error or "ECOSYSTEM_POLICY_FORBIDDEN",
                "code": "ECOSYSTEM_POLICY_FORBIDDEN",
                "intent": intent.to_dict(),
            }

        if intent.intent == "ecosystem.freeze":
            if self.policy_engine is not None:
                state = self.policy_engine.freeze(
                    initiated_by=caller_id,
                    reason=intent.parameters.get("reason", "Operator requested voice freeze"),
                    channel="voice",
                )
                return {
                    "success": True,
                    "intent": intent.to_dict(),
                    "frozen": True,
                    "policy_version": state.get("policy_version"),
                    "spoken_response": "Emergency freeze engaged. All automations and active scans are suspended.",
                }
            return {
                "success": True,
                "intent": intent.to_dict(),
                "frozen": True,
                "spoken_response": "Freeze command received.",
            }

        elif intent.intent == "scan.request":
            target_dev = intent.target.get("device_id") or caller_device_id
            profile = intent.parameters.get("profile", "quick")

            if self.policy_engine is not None:
                from ecosystem_policy.engine import ActionRequest
                decision = self.policy_engine.decide(ActionRequest(
                    actor=caller_id,
                    action="zbt_scan",
                    action_class="investigate",
                    target={"device_id": target_dev},
                    context={"profile": profile, "trigger": "voice"},
                    authenticated=True,
                ))
                if decision.result == "deny":
                    return {
                        "success": False,
                        "intent": intent.to_dict(),
                        "error": decision.reason,
                        "spoken_response": f"Scan rejected: {decision.reason}",
                    }

            if self.scan_runner is not None:
                from agents.scan_agent import ScanRequest
                scan_res = await self.scan_runner.run_scan(ScanRequest(
                    device_id=target_dev,
                    profile=profile,
                    initiator=caller_id,
                    trigger="voice",
                ))
                return {
                    "success": scan_res.status not in ("error", "denied"),
                    "intent": intent.to_dict(),
                    "scan_id": scan_res.scan_id,
                    "status": scan_res.status,
                    "spoken_response": f"Scan for {target_dev} completed with status: {scan_res.status}.",
                }

            return {
                "success": True,
                "intent": intent.to_dict(),
                "spoken_response": f"Scan requested for {target_dev}.",
            }

        elif intent.intent == "scan.results":
            target_dev = intent.target.get("device_id") or caller_device_id
            if self.scan_runner is not None:
                scans = self.scan_runner.list_scans(device_id=target_dev)
                latest = scans[0] if scans else None
                if latest:
                    return {
                        "success": True,
                        "intent": intent.to_dict(),
                        "scan": latest.to_dict(),
                        "spoken_response": f"Latest scan for {target_dev} is {latest.status}, completed at {latest.completed_at}.",
                    }
                return {
                    "success": True,
                    "intent": intent.to_dict(),
                    "scan": None,
                    "spoken_response": f"No scan results on record for {target_dev}.",
                }
            return {
                "success": True,
                "intent": intent.to_dict(),
                "spoken_response": "Scan service not available.",
            }

        elif intent.intent == "automation.run":
            auto_name = intent.parameters.get("automation_name", "routine")
            return {
                "success": True,
                "intent": intent.to_dict(),
                "automation": auto_name,
                "spoken_response": f"Automation {auto_name} dispatched.",
            }

        return {
            "success": False,
            "intent": intent.to_dict(),
            "error": intent.error or "Unknown voice intent",
            "spoken_response": "I did not recognize that command.",
        }

    async def handle_text_utterance(
        self,
        text: str,
        *,
        caller_id: str = "voice_operator",
        caller_device_id: str = "local",
    ) -> dict[str, Any]:
        intent = self.parser.parse(text, caller_device_id=caller_device_id)
        return await self.execute_intent(intent, caller_id=caller_id, caller_device_id=caller_device_id)

    async def handle_audio_stream(
        self,
        audio_pcm: bytes,
        *,
        caller_id: str = "voice_operator",
        caller_device_id: str = "local",
        sample_rate: int = 16000,
    ) -> dict[str, Any]:
        transcription = await self.transcriber.transcribe_pcm(audio_pcm, sample_rate=sample_rate)
        intent = self.parser.parse(transcription, caller_device_id=caller_device_id)
        res = await self.execute_intent(intent, caller_id=caller_id, caller_device_id=caller_device_id)
        res["transcription"] = transcription
        return res


router = APIRouter(prefix="/voice", tags=["voice"])


def get_voice_service(request: Request) -> VoiceService:
    vs = getattr(request.app.state, "voice_service", None)
    if vs is None:
        # Fallback to local on-the-fly instance using app state singletons
        pe = getattr(request.app.state, "policy_engine", None)
        eb = getattr(request.app.state, "event_bus", None)
        sr = getattr(request.app.state, "scan_runner", None)
        vs = VoiceService(policy_engine=pe, event_bus=eb, scan_runner=sr)
        request.app.state.voice_service = vs
    return vs


@router.post("/intent")
async def post_voice_intent(
    body: dict[str, Any] = Body(...),
    voice_service: VoiceService = Depends(get_voice_service),
):
    """Parse text utterance into structured intent, verify policy, and execute."""
    text = str(body.get("text") or "").strip()
    caller_id = str(body.get("caller_id") or "voice_operator").strip()
    caller_device_id = str(body.get("caller_device_id") or "local").strip()

    if not text:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Text utterance is required")

    res = await voice_service.handle_text_utterance(
        text,
        caller_id=caller_id,
        caller_device_id=caller_device_id,
    )
    if not res.get("success") and res.get("code") == "ECOSYSTEM_POLICY_FORBIDDEN":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=res["error"])
    return res


@router.get("/status")
async def get_voice_status(
    voice_service: VoiceService = Depends(get_voice_service),
):
    """Return voice service status and tier-scaled configuration."""
    return {
        "status": "ready",
        "tier": voice_service.transcriber.tier,
        "model": voice_service.transcriber.model_name,
        "capabilities": [
            "ecosystem.freeze",
            "scan.request",
            "scan.results",
            "automation.run",
        ],
        "zero_retention": True,
    }

