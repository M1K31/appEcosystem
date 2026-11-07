"""FastAPI routes for `ecosystem-scan` agent, report retrieval, and auto-scan targets."""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status

logger = logging.getLogger("ecosystem.scan_routes")


async def _require_scan_auth(request: Request) -> dict | None:
    """Gate every scan route: allow HMAC-authenticated service callers or
    loopback operator-UI sessions, reject remote unauthenticated callers.

    Scan data (device inventories, forensic reports, scan triggering) is
    sensitive, so reuse the same gate the policy routes apply.
    """
    from .policy_routes import _optional_auth, _require_loopback_or_auth

    auth = await _optional_auth(request)
    _require_loopback_or_auth(request, auth)
    return auth


router = APIRouter(
    prefix="/scans",
    tags=["scans"],
    dependencies=[Depends(_require_scan_auth)],
)


def get_scan_runner(request: Request):
    runner = getattr(request.app.state, "scan_runner", None)
    if runner is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan runner not initialized",
        )
    return runner


def get_scan_scheduler(request: Request):
    sched = getattr(request.app.state, "scan_scheduler", None)
    if sched is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan scheduler not initialized",
        )
    return sched


def get_step_up(request: Request):
    su = getattr(request.app.state, "step_up_auth", None)
    if su is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Step-up authenticator not initialized",
        )
    return su


def _require_step_up(
    request: Request,
    body: dict[str, Any] | None = None,
    step_up_svc: Any = None,
    required_scope: str = "data_release",
) -> dict[str, Any]:
    b = body or {}
    token = (
        b.get("step_up_token")
        or request.headers.get("X-Ecosystem-Step-Up")
        or ""
    ).strip()
    if token and step_up_svc is not None:
        claims = step_up_svc.verify_step_up_token(token, required_scope=required_scope)
        if claims:
            return claims

    # Support inline TOTP code via headers, query params, or body
    totp_code = (
        request.headers.get("X-Ecosystem-TOTP")
        or b.get("totp_code")
        or ""
    ).strip()
    operator_id = str(
        request.headers.get("X-Ecosystem-Operator")
        or b.get("operator_id")
        or "admin"
    ).strip()
    if totp_code and len(totp_code) == 6 and totp_code.isdigit() and step_up_svc is not None:
        issued = step_up_svc.verify_totp_and_issue_token(operator_id, totp_code, scope=required_scope)
        if issued:
            claims = step_up_svc.verify_step_up_token(issued["step_up_token"], required_scope=required_scope)
            if claims:
                return claims

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Decryption of sensitive full scan reports requires valid step-up authentication (TOTP or passkey)",
    )


@router.post("/run")
async def run_scan(
    request: Request,
    body: dict[str, Any] = Body(default_factory=dict),
    runner=Depends(get_scan_runner),
    auth: dict | None = Depends(_require_scan_auth),
):
    """Initiate an on-demand scan with PolicyEngine gating."""
    from agents.scan_agent import ScanRequest

    device_id = str(body.get("device_id") or "local").strip()
    profile = str(body.get("profile") or "quick").strip().lower()
    offline = bool(body.get("offline", False))
    # Initiator is the authenticated service identity, never taken from the
    # request body (which a caller could forge). Loopback operator UI → "operator".
    initiator = str((auth or {}).get("app_id") or "operator").strip()
    phone_folder = body.get("phone_folder")
    fp = body.get("public_key_fingerprint")

    scan_req = ScanRequest(
        device_id=device_id,
        public_key_fingerprint=fp,
        profile=profile,
        offline=offline,
        initiator=initiator,
        trigger="on_demand",
        phone_folder=phone_folder,
    )
    result = await runner.run_scan(scan_req)
    return result.to_dict()


@router.get("")
async def list_scans(
    device_id: Optional[str] = Query(None),
    runner=Depends(get_scan_runner),
):
    """List historical scan summaries."""
    scans = runner.list_scans(device_id=device_id)
    return [s.to_dict() for s in scans]


@router.get("/targets")
async def list_targets(
    scheduler=Depends(get_scan_scheduler),
):
    """List enrolled scan targets with their auto_scan authorization and reachable status."""
    return await scheduler.check_enrolled_targets()


@router.post("/targets/run-due")
async def run_due_scans(
    scheduler=Depends(get_scan_scheduler),
):
    """Trigger scheduled scans for reachable, authorized devices."""
    results = await scheduler.run_due_scans()
    return [r.to_dict() for r in results]


@router.get("/{scan_id}")
async def get_scan_summary(
    scan_id: str,
    runner=Depends(get_scan_runner),
):
    """Get redacted share.json summary and status for a scan."""
    scan = runner.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan.to_dict()


@router.get("/{scan_id}/full")
async def get_scan_full_report(
    scan_id: str,
    request: Request,
    runner=Depends(get_scan_runner),
    step_up=Depends(get_step_up),
):
    """Decrypt and return the full forensic report. Requires step-up auth via the
    X-Ecosystem-Step-Up / X-Ecosystem-TOTP headers (or POST body) — never URL query
    params, which leak into access logs and browser history."""
    _require_step_up(
        request,
        step_up_svc=step_up,
        required_scope="data_release",
    )
    try:
        report = runner.decrypt_full_report(scan_id)
        return report
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        logger.error("Failed decrypting report for %s: %r", scan_id, exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed decrypting report")
