"""Voice intent parsing and strict privilege boundary enforcement."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class VoiceIntent:
    intent: str  # ecosystem.freeze | scan.request | scan.results | automation.run | forbidden | unknown
    action: str
    confidence: float
    raw_text: str
    parameters: dict[str, Any] = field(default_factory=dict)
    target: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def is_forbidden(self) -> bool:
        return self.intent == "forbidden"

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent": self.intent,
            "action": self.action,
            "confidence": self.confidence,
            "raw_text": self.raw_text,
            "parameters": self.parameters,
            "target": self.target,
            "error": self.error,
        }


class IntentParser:
    """Parses transcribed voice utterances into structured intents with strict security checks."""

    # Explicitly forbidden voice actions (cannot be triggered via voice)
    _FORBIDDEN_PATTERNS = [
        re.compile(r"\b(resume|unfreeze|un-freeze)\b", re.IGNORECASE),
        re.compile(r"\b(restrictions?\s*(off|disable|turn off))\b", re.IGNORECASE),
        re.compile(r"\b(approve|approval|confirm checkpoint|grant override)\b", re.IGNORECASE),
        re.compile(r"\b(deny|reject)\b", re.IGNORECASE),
    ]

    _FREEZE_PATTERNS = [
        re.compile(r"\b(freeze\s*(ecosystem|automations?|all|everything)?)\b", re.IGNORECASE),
        re.compile(r"\b(emergency\s*freeze)\b", re.IGNORECASE),
        re.compile(r"\b(stop\s*all\s*automations?)\b", re.IGNORECASE),
        re.compile(r"\b(pause\s*automations?)\b", re.IGNORECASE),
    ]

    _SCAN_REQUEST_PATTERNS = [
        re.compile(r"\b(scan\s*(my\s*)?(designated\s*)?(workstation|device|endpoint|computer|laptop)?)\b", re.IGNORECASE),
        re.compile(r"\b(run\s*(a\s*)?(quick\s*)?scan)\b", re.IGNORECASE),
        re.compile(r"\b(run\s*security\s*checks?)\b", re.IGNORECASE),
        re.compile(r"\b(check\s*for\s*(spyware|breach|malware))\b", re.IGNORECASE),
    ]

    _SCAN_RESULTS_PATTERNS = [
        re.compile(r"\b(show|get|what are)\s*(the\s*)?scan\s*results?\b", re.IGNORECASE),
        re.compile(r"\b(scan\s*status)\b", re.IGNORECASE),
        re.compile(r"\b(latest\s*scan)\b", re.IGNORECASE),
    ]

    _AUTOMATION_PATTERNS = [
        re.compile(r"\b(run|trigger|execute)\s*evening\s*security\s*checks?\b", re.IGNORECASE),
        re.compile(r"\b(run|trigger)\s*automation\s*(?P<name>[\w\-]+)?\b", re.IGNORECASE),
    ]

    def parse(self, text: str, *, caller_device_id: str = "local") -> VoiceIntent:
        cleaned = (text or "").strip()
        if not cleaned:
            return VoiceIntent(
                intent="unknown",
                action="none",
                confidence=0.0,
                raw_text="",
                error="Empty voice transcription",
            )

        # 1. Check for FORBIDDEN privileged transitions
        for pat in self._FORBIDDEN_PATTERNS:
            if pat.search(cleaned):
                return VoiceIntent(
                    intent="forbidden",
                    action="privileged_transition_rejected",
                    confidence=1.0,
                    raw_text=cleaned,
                    error=(
                        "ECOSYSTEM_POLICY_FORBIDDEN: Voice intents cannot resume from Freeze, "
                        "approve checkpoints, or turn Restrictions: Off. Authenticated operator "
                        "step-up authentication (TOTP or Passkey) is strictly required."
                    ),
                )

        # 2. Check Freeze intent
        for pat in self._FREEZE_PATTERNS:
            if pat.search(cleaned):
                return VoiceIntent(
                    intent="ecosystem.freeze",
                    action="freeze",
                    confidence=0.95,
                    raw_text=cleaned,
                    parameters={"reason": f"Voice intent: '{cleaned}'"},
                    target={"scope": "ecosystem"},
                )

        # 3. Check Scan results intent
        for pat in self._SCAN_RESULTS_PATTERNS:
            if pat.search(cleaned):
                return VoiceIntent(
                    intent="scan.results",
                    action="get_latest",
                    confidence=0.90,
                    raw_text=cleaned,
                    target={"device_id": caller_device_id},
                )

        # 4. Check Scan request intent
        for pat in self._SCAN_REQUEST_PATTERNS:
            if pat.search(cleaned):
                is_full = bool(re.search(r"\b(full|deep)\b", cleaned, re.IGNORECASE))
                profile = "full" if is_full else "quick"
                return VoiceIntent(
                    intent="scan.request",
                    action="run_scan",
                    confidence=0.92,
                    raw_text=cleaned,
                    parameters={"profile": profile},
                    target={"device_id": caller_device_id},
                )

        # 5. Check Automation run intent
        for pat in self._AUTOMATION_PATTERNS:
            m = pat.search(cleaned)
            if m:
                name = m.groupdict().get("name") or "evening_security_checks"
                return VoiceIntent(
                    intent="automation.run",
                    action="execute_rule",
                    confidence=0.88,
                    raw_text=cleaned,
                    parameters={"automation_name": name},
                )

        # 6. Unmatched
        return VoiceIntent(
            intent="unknown",
            action="none",
            confidence=0.0,
            raw_text=cleaned,
            error=f"Unrecognized voice command: '{cleaned}'",
        )

