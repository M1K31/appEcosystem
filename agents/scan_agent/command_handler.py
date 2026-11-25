"""WP6 Command Handler for `scan.request` capability (`action_class='investigate'`).

Registers ZBT scans on the hub's capability network with a schema-valid
`capability-manifest.v1` manifest so any authorized app (AI-for-Survival,
AegisSIEM, OpenEye, voice) can invoke `scan.request` through WP1's signed,
policy-gated, audited command dispatcher.
"""
from __future__ import annotations

import re
from typing import Any, Awaitable, Callable

from .runner import ScanRequest, ScanRunner

SCAN_PROVIDER_APP = "ecosystem_scan_agent"

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
    "schema_version": 1,
    "capability": "scan.request",
    "version": 1,
    "description": (
        "Run an authorized, read-only Zero Breach Toolkit (ZBT) scan against "
        "an enrolled device with recorded AUP consent or an allowlisted phone backup folder."
    ),
    "provider": {
        "app": SCAN_PROVIDER_APP,
        "device_id": "hub-local",
    },
    "action_class": "investigate",
    "required_grant": "scan:request",
    "inputs_schema": SCAN_REQUEST_SCHEMA,
    "timeout_seconds": 600,
    "cancellable": True,
    "idempotent": False,
    "offline_behavior": "run_local",
}

_HOST_PATH_RE = re.compile(r"(?:/[A-Za-z0-9._-]+){2,}|[A-Za-z]:\\[^\s\"']+")


def _redact_diagnostic(msg: str | None) -> str | None:
    if not msg:
        return None
    cleaned = _HOST_PATH_RE.sub("[redacted-path]", str(msg))
    return cleaned[:240]


def _sanitize_public_result(raw: dict[str, Any]) -> dict[str, Any]:
    """Strip host filesystem paths and raw subprocess/exception diagnostics."""
    public = dict(raw)
    has_full = bool(public.pop("report_ref", ""))
    public["has_full_report"] = has_full

    if public.get("error_message"):
        # Only expose safe high-level status; never leak raw subprocess stderr or paths
        st = str(public.get("status") or "unknown")
        if st in ("denied", "needs_approval", "deferred"):
            public["error_message"] = _redact_diagnostic(public["error_message"])
        else:
            public["error_message"] = f"Scan ended with status '{st}'"

    share = public.get("share")
    if isinstance(share, dict):
        safe_share = dict(share)
        if "error" in safe_share:
            safe_share["error"] = "Scan summary unavailable"
        public["share"] = safe_share
    return public


def build_scan_request_handler(
    runner: ScanRunner,
) -> Callable[[dict[str, Any], str | None], Awaitable[dict[str, Any]]]:
    """Build an in-hub local command handler for `scan.request`."""

    async def _handle(
        record: dict[str, Any],
        authorization_ref: str | None = None,
    ) -> dict[str, Any]:
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
            authorization_ref=authorization_ref,
        )
        res = await runner.run_scan(req)
        public_res = _sanitize_public_result(res.to_dict())

        if res.status == "denied":
            return {
                "status": "denied",
                "error": public_res.get("error_message") or "Scan denied by policy",
                "result": public_res,
            }
        if res.status == "needs_approval":
            # If an operator approval was already supplied, do not loop back to pending_approval
            if authorization_ref:
                return {
                    "status": "failed",
                    "error": "Operator approval did not satisfy scan runner policy gate",
                    "result": public_res,
                }
            return {
                "status": "pending_approval",
                "error": public_res.get("error_message") or "Scan requires operator approval",
                "result": public_res,
            }
        return {"status": "completed", "result": public_res}

    return _handle
