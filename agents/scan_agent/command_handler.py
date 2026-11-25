"""WP6 Command Handler for `scan.request` capability (`action_class='investigate'`).

Registers ZBT scans on the hub's capability network so any authorized app
(AI-for-Survival, AegisSIEM, OpenEye, voice) can invoke `scan.request`
through WP1's signed, policy-gated, audited command dispatcher.
"""
from __future__ import annotations

from typing import Any, Awaitable, Callable

from .runner import ScanRequest, ScanRunner

SCAN_REQUEST_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "target_device": {"type": "string", "minLength": 1, "maxLength": 128},
        "phone_folder": {"type": "string", "minLength": 1, "maxLength": 1024},
        "profile": {"type": "string", "enum": ["quick", "standard", "full"]},
        "offline": {"type": "boolean"},
        "public_key_fingerprint": {"type": "string", "maxLength": 256},
    },
    "additionalProperties": False,
}

SCAN_REQUEST_CAPABILITY: dict[str, Any] = {
    "capability": "scan.request",
    "version": "1.0",
    "action_class": "investigate",
    "description": (
        "Run an authorized, read-only Zero Breach Toolkit (ZBT) scan against "
        "an enrolled device with recorded AUP consent or an allowlisted phone backup folder."
    ),
    "input_schema": SCAN_REQUEST_SCHEMA,
}


def build_scan_request_handler(
    runner: ScanRunner,
) -> Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]:
    """Build an in-hub local command handler for `scan.request`."""

    async def _handle(record: dict[str, Any]) -> dict[str, Any]:
        params = dict(record.get("parameters") or {})
        target = record.get("target") or {}
        actor = record.get("actor") or {}

        target_device = (
            params.get("target_device")
            or (target.get("identifier") if isinstance(target, dict) else None)
            or "local"
        )
        phone_folder = params.get("phone_folder")
        profile = str(params.get("profile") or "quick").strip().lower()
        if profile not in ("quick", "standard", "full"):
            profile = "quick"
        offline = bool(params.get("offline", True))
        fp = params.get("public_key_fingerprint")
        initiator = str(actor.get("app") or actor.get("id") or "ecosystem_hub").strip()

        req = ScanRequest(
            device_id=str(target_device).strip(),
            public_key_fingerprint=str(fp).strip() if fp else None,
            profile=profile,
            offline=offline,
            initiator=initiator,
            trigger="command_dispatch",
            phone_folder=str(phone_folder) if phone_folder else None,
        )
        res = await runner.run_scan(req)

        # Never leak raw host filesystem paths in command results
        public_res = res.to_dict()
        has_full = bool(public_res.pop("report_ref", ""))
        public_res["has_full_report"] = has_full

        if res.status in ("denied", "needs_approval"):
            return {
                "status": "denied" if res.status == "denied" else "pending_approval",
                "error": res.error_message or res.exit_description,
                "result": public_res,
            }
        return {"status": "completed", "result": public_res}

    return _handle
