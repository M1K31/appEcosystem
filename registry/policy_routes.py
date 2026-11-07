"""FastAPI routes for `ecosystem-policy`, step-up auth, unified approvals, and the Apple HIG Control Plane UI (:8500)."""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse, HTMLResponse

from ecosystem_auth.tokens import sign_request

logger = logging.getLogger(__name__)

router = APIRouter()

REPO_ROOT = Path(__file__).resolve().parent.parent


def _ensure_policy_pkg() -> None:
    policy_pkg = REPO_ROOT / "packages" / "ecosystem-policy"
    if policy_pkg.is_dir() and str(policy_pkg) not in sys.path:
        sys.path.insert(0, str(policy_pkg))


def get_policy_engine(request: Request):
    eng = getattr(request.app.state, "policy_engine", None)
    if eng is None:
        raise HTTPException(status_code=503, detail="Policy engine not initialized")
    return eng


def get_step_up(request: Request):
    su = getattr(request.app.state, "step_up_auth", None)
    if su is None:
        raise HTTPException(status_code=503, detail="Step-up authenticator not initialized")
    return su


def get_approval_service(request: Request):
    svc = getattr(request.app.state, "approval_service", None)
    if svc is None:
        raise HTTPException(status_code=503, detail="Approval service not initialized")
    return svc


def _require_loopback_or_auth(request: Request, auth: dict | None) -> None:
    """Allow either HMAC-authenticated service callers or loopback operator UI sessions."""
    if auth is not None:
        return
    if request.headers.get("x-forwarded-for"):
        raise HTTPException(status_code=401, detail="Ecosystem authentication required for remote callers")
    host = (request.client.host if request.client else "") or ""
    if host not in ("127.0.0.1", "::1", "localhost", "testclient"):
        raise HTTPException(status_code=401, detail="Ecosystem authentication required for non-loopback callers")


async def _optional_auth(request: Request) -> dict | None:
    from .app import require_registry_auth
    from ecosystem_auth.middleware import security_scheme

    has_sig = bool(request.headers.get("X-Ecosystem-Signature"))
    has_bearer = bool(request.headers.get("Authorization"))
    if not has_sig and not has_bearer:
        return None
    creds = await security_scheme(request)
    return await require_registry_auth(request, creds)


def _resolve_step_up_claims(
    step_up_svc: Any,
    body: dict[str, Any],
    request: Request,
    *,
    required_scope: str = "policy_admin",
) -> dict[str, Any]:
    token = (
        body.get("step_up_token")
        or request.headers.get("X-Ecosystem-Step-Up")
        or ""
    ).strip()
    if token:
        claims = step_up_svc.verify_step_up_token(token, required_scope=required_scope)
        if claims:
            return claims

    # Support inline TOTP verification in one request (used by `<ecosystem-override-modal>`)
    operator_id = str(body.get("operator_id") or "admin").strip()
    totp_code = str(body.get("totp_code") or body.get("step_up_credential") or "").strip()
    if totp_code and len(totp_code) == 6 and totp_code.isdigit():
        issued = step_up_svc.verify_totp_and_issue_token(operator_id, totp_code, scope=required_scope)
        if issued:
            claims = step_up_svc.verify_step_up_token(issued["step_up_token"], required_scope=required_scope)
            if claims:
                return claims

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Valid TOTP 2FA, WebAuthn Passkey, or Device-Key step-up authentication required",
    )


def _duration_to_seconds(raw: Any) -> tuple[int | None, bool]:
    if raw == "until_revoked":
        return None, True
    if isinstance(raw, (int, float)):
        return max(60, int(raw)), False
    s = str(raw or "30m").strip().lower()
    mapping = {"15m": 900, "30m": 1800, "1h": 3600, "4h": 14400}
    if s in mapping:
        return mapping[s], False
    if s.endswith("m") and s[:-1].isdigit():
        return max(60, int(s[:-1]) * 60), False
    if s.endswith("h") and s[:-1].isdigit():
        return max(60, int(s[:-1]) * 3600), False
    if s.isdigit():
        return max(60, int(s)), False
    return 1800, False


async def _fanout_peer_sync(request: Request, event_type: str, state: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Notify registered healthy/known peers of a freeze or policy state update and track acknowledgments."""
    reg = getattr(request.app.state, "registry", None)
    if reg is None:
        return ["hub-local"], []
    from ecosystem_auth.tokens import get_ecosystem_secret

    try:
        secret = get_ecosystem_secret()
    except Exception:
        secret = ""

    ack: list[str] = ["hub-local"]
    unreachable: list[str] = []
    services = reg.get_all()
    for svc in services:
        svc_status = str(getattr(svc.status, "value", svc.status))
        if svc.static and svc_status != "healthy":
            continue
        url = svc.webhook_url or f"http://{svc.host}:{svc.port}{svc.metadata.get('webhook_path') or '/ecosystem/events'}"
        envelope = {
            "schema_version": 2,
            "type": event_type,
            "source": "registry",
            "data": state,
        }
        headers = sign_request("POST", url, secret, body=envelope) if secret else {}
        try:
            async with httpx.AsyncClient(timeout=1.5) as client:
                r = await client.post(url, json=envelope, headers=headers)
                if r.status_code < 400:
                    ack.append(svc.name)
                else:
                    unreachable.append(svc.name)
        except Exception:
            unreachable.append(svc.name)
    return ack, unreachable


# ---- Policy State & Evaluation Routes ---------------------------------------

@router.get("/policy/state")
async def get_policy_state(engine=Depends(get_policy_engine)):
    """Return canonical `policy-state.v1` JSON for `<ecosystem-policy-bar>` across all dashboards."""
    return engine.export_state()


@router.get("/policy/audit")
async def get_policy_audit(
    limit: int = 100,
    request: Request = None,  # type: ignore[assignment]
    engine=Depends(get_policy_engine),
):
    auth = await _optional_auth(request)
    _require_loopback_or_auth(request, auth)
    return {"audit": engine.audit_log(limit=limit)}


@router.post("/policy/decide")
async def evaluate_policy_decision(
    request: Request,
    payload: dict[str, Any] = Body(...),
    engine=Depends(get_policy_engine),
    approvals=Depends(get_approval_service),
):
    """Evaluate an `ActionRequest`; optionally auto-enqueue an approval record when required or async."""
    _ensure_policy_pkg()
    from ecosystem_policy.models import ActionRequest

    auth = await _optional_auth(request)
    _require_loopback_or_auth(request, auth)

    req = ActionRequest(
        actor=str(payload.get("actor") or "unknown"),
        action=str(payload.get("action") or ""),
        action_class=str(payload.get("action_class") or ""),
        target=payload.get("target") or {},
        model=payload.get("model"),
        context=payload.get("context") or {},
        rationale=str(payload.get("rationale") or ""),
        authenticated=bool(payload.get("authenticated", True)),
    )
    decision = engine.decide(req)
    out = decision.to_dict()

    if payload.get("enqueue_approval", False) and (
        decision.result == "require_approval" or decision.async_approval
    ):
        rec = await approvals.create_request(
            {
                "requester_service": req.app_name,
                "actor": req.actor,
                "action": req.action,
                "action_class": req.action_class,
                "target": req.target,
                "summary": req.rationale or f"{req.actor}: {req.action}",
                "policy_version": decision.policy_version,
                "mode": decision.mode,
                "ttl_seconds": decision.ttl_seconds or 3600,
                "async_containment": decision.async_approval,
                "on_deny": decision.on_deny,
                "revert_plan": decision.revert_plan,
            }
        )
        out["approval"] = rec
    return out


@router.post("/policy/freeze")
async def activate_freeze(
    request: Request,
    payload: dict[str, Any] = Body(default={}),
    engine=Depends(get_policy_engine),
):
    """Engage emergency Freeze locally first, then fan out to reachable peers and report sync status."""
    auth = await _optional_auth(request)
    _require_loopback_or_auth(request, auth)

    initiated_by = str(payload.get("initiated_by") or (auth or {}).get("app_id") or "local-operator")
    reason = str(payload.get("reason") or "Emergency Freeze activated")
    channel = str(payload.get("channel") or "ui")

    # 1. Freeze locally first so no local decisions slip through during network fanout
    initial_state = engine.freeze(
        initiated_by=initiated_by,
        reason=reason,
        channel=channel,
        acknowledged_devices=["hub-local"],
    )
    ack, unreachable = await _fanout_peer_sync(request, "policy.freeze", initial_state)
    final_state = engine.freeze(
        initiated_by=initiated_by,
        reason=reason,
        channel=channel,
        acknowledged_devices=ack,
        unreachable_devices=unreachable,
    )
    return final_state


@router.post("/policy/resume")
async def resume_from_freeze(
    request: Request,
    payload: dict[str, Any] = Body(default={}),
    engine=Depends(get_policy_engine),
    step_up=Depends(get_step_up),
):
    """Clear Freeze — strictly requires authenticated step-up verification (TOTP / Passkey / Device Key)."""
    auth = await _optional_auth(request)
    _require_loopback_or_auth(request, auth)
    claims = _resolve_step_up_claims(step_up, payload, request)

    state = engine.resume(
        operator_id=str(claims["sub"]),
        auth_method=str(claims["amr"]),
        reason=str(payload.get("reason") or "Operator resumed operations"),
    )
    await _fanout_peer_sync(request, "policy.resume", state)
    return state


@router.post("/policy/restrictions/off")
async def set_restrictions_off(
    request: Request,
    payload: dict[str, Any] = Body(...),
    engine=Depends(get_policy_engine),
    step_up=Depends(get_step_up),
):
    """Issue an Ed25519-signed, timed, scoped `Restrictions: Off` grant (requires step-up auth)."""
    auth = await _optional_auth(request)
    _require_loopback_or_auth(request, auth)
    claims = _resolve_step_up_claims(step_up, payload, request)

    scope = payload.get("scope") or {}
    apps = scope.get("apps") or payload.get("apps") or []
    devices = scope.get("devices") or payload.get("devices") or []
    action_classes = scope.get("action_classes") or payload.get("actionClasses") or payload.get("action_classes") or []
    dur_sec, until_revoked = _duration_to_seconds(payload.get("duration") or payload.get("duration_seconds"))
    if payload.get("until_revoked") or payload.get("untilRevoked"):
        until_revoked = True

    try:
        provisional = engine.activate_restrictions_off(
            issued_by=str(claims["sub"]),
            auth_method=str(claims["amr"]),
            reason=str(payload.get("reason") or ""),
            apps=list(apps),
            devices=list(devices),
            action_classes=list(action_classes),
            duration_seconds=dur_sec,
            until_revoked=until_revoked,
            applied_devices=["hub-local"],
        )
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    ack, unreachable = await _fanout_peer_sync(request, "policy.restrictions_changed", provisional)
    return engine.activate_restrictions_off(
        issued_by=str(claims["sub"]),
        auth_method=str(claims["amr"]),
        reason=str(payload.get("reason") or ""),
        apps=list(apps),
        devices=list(devices),
        action_classes=list(action_classes),
        duration_seconds=dur_sec,
        until_revoked=until_revoked,
        applied_devices=ack,
        unreachable_devices=unreachable,
    )


@router.post("/policy/restrictions/on")
async def set_restrictions_on(
    request: Request,
    payload: dict[str, Any] = Body(default={}),
    engine=Depends(get_policy_engine),
):
    """Immediately restore conservative `Restrictions: On` posture."""
    auth = await _optional_auth(request)
    _require_loopback_or_auth(request, auth)
    state = engine.restore_restrictions_on(
        actor=str(payload.get("actor") or (auth or {}).get("app_id") or "operator"),
        reason=str(payload.get("reason") or "Operator restored Restrictions: On"),
    )
    await _fanout_peer_sync(request, "policy.restrictions_changed", state)
    return state


@router.post("/policy/mode")
async def change_policy_mode(
    request: Request,
    payload: dict[str, Any] = Body(...),
    engine=Depends(get_policy_engine),
    step_up=Depends(get_step_up),
):
    auth = await _optional_auth(request)
    _require_loopback_or_auth(request, auth)
    claims = _resolve_step_up_claims(step_up, payload, request)
    try:
        return engine.set_mode(
            str(payload.get("mode") or "normal"),
            operator_id=str(claims["sub"]),
            auth_method=str(claims["amr"]),
            verified_incident_id=payload.get("verified_incident_id"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ---- Device Enrollment & Auto-Scan Grant Routes -----------------------------

@router.get("/policy/devices")
async def list_devices_and_grants(
    request: Request,
    engine=Depends(get_policy_engine),
):
    auth = await _optional_auth(request)
    _require_loopback_or_auth(request, auth)
    return {
        "devices": engine.list_enrolled_devices(),
        "auto_scan_grants": engine.list_auto_scan_grants(),
    }


@router.post("/policy/devices/enroll")
async def enroll_device_aup(
    request: Request,
    payload: dict[str, Any] = Body(...),
    engine=Depends(get_policy_engine),
):
    auth = await _optional_auth(request)
    _require_loopback_or_auth(request, auth)
    device_id = str(payload.get("device_id") or "").strip()
    fp = str(payload.get("public_key_fingerprint") or "").strip()
    owner = str(payload.get("owner") or "owner").strip()
    if not device_id or not fp:
        raise HTTPException(status_code=400, detail="device_id and public_key_fingerprint are required")
    rec = engine.enroll_device(
        device_id=device_id,
        public_key_fingerprint=fp,
        owner=owner,
        aup_version=str(payload.get("aup_version") or "1.0"),
        scopes=payload.get("scopes"),
    )
    return rec.to_dict()


@router.post("/policy/auto-scan/grants")
async def create_auto_scan_grant(
    request: Request,
    payload: dict[str, Any] = Body(...),
    engine=Depends(get_policy_engine),
    step_up=Depends(get_step_up),
):
    auth = await _optional_auth(request)
    _require_loopback_or_auth(request, auth)
    _resolve_step_up_claims(step_up, payload, request)
    device_id = str(payload.get("device_id") or "").strip()
    if not device_id:
        raise HTTPException(status_code=400, detail="device_id is required")
    try:
        grant = engine.designate_auto_scan(
            device_id,
            profiles=payload.get("profiles"),
            scopes=payload.get("scopes"),
            initiators=payload.get("initiators"),
            authorization_ref=str(payload.get("authorization_ref") or "owner-explicit-designation"),
            expires_at=payload.get("expires_at"),
        )
        return grant.to_dict()
    except PermissionError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.delete("/policy/auto-scan/grants/{device_id}")
async def revoke_auto_scan_grant(
    device_id: str,
    request: Request,
    engine=Depends(get_policy_engine),
):
    auth = await _optional_auth(request)
    _require_loopback_or_auth(request, auth)
    revoked = engine.revoke_auto_scan(device_id)
    if not revoked:
        raise HTTPException(status_code=404, detail=f"No active auto_scan grant for '{device_id}'")
    return {"status": "revoked", "device_id": device_id}


# ---- Step-Up Authentication Routes (TOTP 2FA & WebAuthn Passkeys) -----------

@router.get("/auth/step-up/status")
async def step_up_status(
    operator_id: str = "admin",
    step_up=Depends(get_step_up),
):
    return {"operator_id": operator_id, "factors": step_up.has_enrolled_factors(operator_id)}


@router.post("/auth/step-up/totp/enroll")
async def enroll_totp(
    request: Request,
    payload: dict[str, Any] = Body(default={}),
    step_up=Depends(get_step_up),
):
    """Enroll TOTP 2FA (loopback-only bootstrap or existing step-up required when already enrolled)."""
    if request.headers.get("x-forwarded-for"):
        raise HTTPException(status_code=404, detail="Not Found")
    host = (request.client.host if request.client else "") or ""
    if host not in ("127.0.0.1", "::1", "localhost", "testclient"):
        raise HTTPException(status_code=404, detail="Not Found")

    operator_id = str(payload.get("operator_id") or "admin").strip()
    existing = step_up.has_enrolled_factors(operator_id)
    if existing.get("totp"):
        # Re-enrolling requires proving current step-up
        _resolve_step_up_claims(step_up, payload, request)
    return step_up.enroll_totp(operator_id)


@router.post("/auth/step-up/totp/verify")
async def verify_totp_code(
    payload: dict[str, Any] = Body(...),
    step_up=Depends(get_step_up),
):
    operator_id = str(payload.get("operator_id") or "admin").strip()
    code = str(payload.get("code") or "").strip()
    res = step_up.verify_totp_and_issue_token(operator_id, code)
    if not res:
        raise HTTPException(status_code=401, detail="Invalid or replayed TOTP code")
    return res


@router.post("/auth/step-up/passkey/register")
async def register_passkey(
    request: Request,
    payload: dict[str, Any] = Body(...),
    step_up=Depends(get_step_up),
):
    if request.headers.get("x-forwarded-for"):
        raise HTTPException(status_code=404, detail="Not Found")
    host = (request.client.host if request.client else "") or ""
    if host not in ("127.0.0.1", "::1", "localhost", "testclient"):
        raise HTTPException(status_code=404, detail="Not Found")

    operator_id = str(payload.get("operator_id") or "admin").strip()
    cred_id = str(payload.get("credential_id") or "").strip()
    pub_key = str(payload.get("public_key") or "").strip()
    if not cred_id or not pub_key:
        raise HTTPException(status_code=400, detail="credential_id and public_key are required")
    return step_up.register_passkey(
        operator_id,
        cred_id,
        pub_key,
        algorithm=str(payload.get("algorithm") or "ES256"),
        label=str(payload.get("label") or "Operator Passkey"),
    )


@router.post("/auth/step-up/passkey/challenge")
async def create_passkey_challenge(
    payload: dict[str, Any] = Body(default={}),
    step_up=Depends(get_step_up),
):
    operator_id = str(payload.get("operator_id") or "admin").strip()
    return step_up.create_challenge(operator_id)


@router.post("/auth/step-up/passkey/verify")
async def verify_passkey_assertion(
    payload: dict[str, Any] = Body(...),
    step_up=Depends(get_step_up),
):
    res = step_up.verify_passkey_assertion_and_issue_token(
        operator_id=str(payload.get("operator_id") or "admin"),
        credential_id=str(payload.get("credential_id") or ""),
        challenge=str(payload.get("challenge") or ""),
        signature_b64=str(payload.get("signature") or ""),
        authenticator_data_b64=payload.get("authenticator_data"),
        client_data_json_b64=payload.get("client_data_json"),
    )
    if not res:
        raise HTTPException(status_code=401, detail="Passkey assertion verification failed")
    return res


# ---- Unified Approvals Routes (`F10`) ---------------------------------------

@router.get("/approvals")
async def list_approvals(
    request: Request,
    status_filter: Optional[str] = None,
    limit: int = 100,
    approvals=Depends(get_approval_service),
):
    auth = await _optional_auth(request)
    _require_loopback_or_auth(request, auth)
    q_status = request.query_params.get("status") or status_filter
    return {"approvals": approvals.list_approvals(status=q_status, limit=limit)}


@router.post("/approvals", status_code=status.HTTP_201_CREATED)
async def create_approval(
    request: Request,
    payload: dict[str, Any] = Body(...),
    approvals=Depends(get_approval_service),
):
    auth = await _optional_auth(request)
    _require_loopback_or_auth(request, auth)
    for req_field in ("action", "action_class"):
        if not payload.get(req_field):
            raise HTTPException(status_code=400, detail=f"Missing required field '{req_field}'")
    return await approvals.create_request(payload)


@router.post("/approvals/{approval_id}/approve")
async def approve_checkpoint(
    approval_id: str,
    request: Request,
    payload: dict[str, Any] = Body(default={}),
    approvals=Depends(get_approval_service),
    step_up=Depends(get_step_up),
):
    auth = await _optional_auth(request)
    _require_loopback_or_auth(request, auth)
    claims = _resolve_step_up_claims(step_up, payload, request)
    # Issue a fresh verified token for queue auditing
    fresh = step_up.issue_step_up_token(str(claims["sub"]), auth_method=str(claims["amr"]))
    try:
        return approvals.approve(
            approval_id,
            step_up_token=fresh["step_up_token"],
            note=str(payload.get("note") or ""),
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@router.post("/approvals/{approval_id}/deny")
async def deny_checkpoint(
    approval_id: str,
    request: Request,
    payload: dict[str, Any] = Body(default={}),
    approvals=Depends(get_approval_service),
    step_up=Depends(get_step_up),
):
    auth = await _optional_auth(request)
    _require_loopback_or_auth(request, auth)
    claims = _resolve_step_up_claims(step_up, payload, request)
    fresh = step_up.issue_step_up_token(str(claims["sub"]), auth_method=str(claims["amr"]))
    try:
        return approvals.deny(
            approval_id,
            step_up_token=fresh["step_up_token"],
            note=str(payload.get("note") or ""),
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


# ---- Apple HIG Control Plane Web UI (:8500/ui) ------------------------------

def _resolve_asset_file(relative_subpath: str) -> Optional[Path]:
    candidates = [
        REPO_ROOT / relative_subpath,
        Path(os.environ.get("ECOSYSTEM_DIR", "")) / relative_subpath,
        Path(os.environ.get("ECOSYSTEM_CONFIG", "")).parent / relative_subpath,
        Path.home() / "GitHub" / "appEcosystem" / relative_subpath,
        Path.home() / ".local" / "share" / "ecosystem" / relative_subpath,
        Path.cwd() / relative_subpath,
    ]
    for c in candidates:
        try:
            if c and c.is_file():
                return c
        except Exception:
            pass
    return None


@router.get("/ui/ecosystem-theme.css")
async def serve_ecosystem_theme():
    css_path = _resolve_asset_file("theme/ecosystem-theme.css")
    if not css_path or not css_path.is_file():
        raise HTTPException(status_code=404, detail="Theme CSS not found")
    return FileResponse(css_path, media_type="text/css")


@router.get("/ui/ecosystem-ui-controls.js")
async def serve_ecosystem_ui_controls():
    js_path = _resolve_asset_file("packages/ecosystem-ui-controls/dist/ecosystem-ui-controls.js")
    if not js_path or not js_path.is_file():
        raise HTTPException(status_code=404, detail="UI controls bundle not found")
    return FileResponse(js_path, media_type="application/javascript")


@router.get("/ui/fonts/{font_name}")
async def serve_ecosystem_font(font_name: str):
    font_path = _resolve_asset_file(f"theme/fonts/{font_name}")
    if not font_path or not font_path.is_file():
        raise HTTPException(status_code=404, detail="Font file not found")
    return FileResponse(font_path, media_type="font/woff2")


CONTROL_PLANE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>appEcosystem Control Plane</title>
  <link rel="stylesheet" href="/ui/ecosystem-theme.css" />
  <script src="/ui/ecosystem-ui-controls.js"></script>
  <style>
    :root {
      color-scheme: light dark;
      --cp-bg: var(--eco-bg-primary, #f5f5f7);
      --cp-card: var(--eco-bg-secondary, #ffffff);
      --cp-text: var(--eco-text-primary, #1d1d1f);
      --cp-muted: var(--eco-text-secondary, #6e6e73);
      --cp-border: rgba(128, 128, 128, 0.2);
      --cp-accent: #0071e3;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --cp-bg: #000000;
        --cp-card: #1c1c1e;
        --cp-text: #f5f5f7;
        --cp-muted: #98989d;
        --cp-border: rgba(255, 255, 255, 0.14);
        --cp-accent: #0a84ff;
      }
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto, sans-serif;
      background: var(--cp-bg);
      color: var(--cp-text);
      line-height: 1.45;
    }
    .shell { max-width: 1240px; margin: 0 auto; padding: 20px 24px 56px; }
    header.topbar {
      display: flex; align-items: center; justify-content: space-between;
      gap: 16px; margin-bottom: 16px; flex-wrap: wrap;
    }
    .brand h1 { font-size: 22px; font-weight: 650; margin: 0; letter-spacing: -0.02em; }
    .brand p { font-size: 13px; color: var(--cp-muted); margin: 2px 0 0; }
    .grid {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
      gap: 18px; margin-top: 20px;
    }
    section.card {
      background: var(--cp-card); border: 1px solid var(--cp-border);
      border-radius: 16px; padding: 18px 20px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.04);
    }
    section.card h2 { font-size: 16px; font-weight: 600; margin: 0 0 12px; }
    .list { display: flex; flex-direction: column; gap: 10px; }
    .item {
      border: 1px solid var(--cp-border); border-radius: 12px; padding: 12px 14px;
      display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap;
    }
    .item-meta { font-size: 12px; color: var(--cp-muted); }
    .btn {
      min-height: 44px; padding: 0 16px; border-radius: 10px; border: 1px solid var(--cp-border);
      background: transparent; color: var(--cp-text); font-size: 14px; font-weight: 600;
      cursor: pointer;
    }
    .btn.primary { background: var(--cp-accent); color: #fff; border-color: transparent; }
    .btn.danger { background: #ff3b30; color: #fff; border-color: transparent; }
    input.totp-input {
      min-height: 44px; padding: 0 12px; border-radius: 10px; border: 1px solid var(--cp-border);
      background: var(--cp-bg); color: var(--cp-text); font-size: 15px; width: 150px;
    }
    .status-toast {
      margin-top: 12px; padding: 10px 14px; border-radius: 10px;
      font-size: 13px; background: rgba(0, 113, 227, 0.12); display: none;
    }
  </style>
</head>
<body>
  <div class="shell">
    <header class="topbar">
      <div class="brand">
        <h1>appEcosystem Control Plane</h1>
        <p>Unified Policy Authority, Step-Up Approvals, Capability Mesh &amp; Device Consent</p>
      </div>
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
        <input id="totpCode" class="totp-input" type="text" inputmode="numeric" maxlength="6" placeholder="6-digit TOTP" aria-label="6-digit TOTP step-up code" />
        <button id="btnEnrollTotp" class="btn" type="button">Setup 2FA</button>
      </div>
    </header>

    <ecosystem-policy-bar id="policyBar" view-mode="admin"></ecosystem-policy-bar>
    <ecosystem-override-modal id="overrideModal"></ecosystem-override-modal>
    <div id="toast" class="status-toast" role="status" aria-live="polite"></div>

    <div class="grid">
      <section class="card" aria-labelledby="approvalsHeading">
        <h2 id="approvalsHeading">Pending Operator Approvals</h2>
        <div id="approvalsList" class="list"><span class="item-meta">Loading approvals…</span></div>
      </section>

      <section class="card" aria-labelledby="capsHeading">
        <h2 id="capsHeading">Project-Contributed Capabilities</h2>
        <div id="capsList" class="list"><span class="item-meta">Loading capabilities…</span></div>
      </section>

      <section class="card" aria-labelledby="servicesHeading">
        <h2 id="servicesHeading">Registered Services &amp; Devices</h2>
        <div id="servicesList" class="list"><span class="item-meta">Loading services…</span></div>
      </section>
    </div>
  </div>

  <script>
    const bar = document.getElementById("policyBar");
    const modal = document.getElementById("overrideModal");
    const toast = document.getElementById("toast");
    const totpInput = document.getElementById("totpCode");

    function showToast(msg) {
      toast.textContent = msg;
      toast.style.display = "block";
      setTimeout(() => { toast.style.display = "none"; }, 6000);
    }

    async function refreshAll() {
      const [pRes, aRes, cRes, sRes] = await Promise.all([
        fetch("/policy/state"),
        fetch("/approvals?status=pending"),
        fetch("/capabilities?active_only=false"),
        fetch("/services")
      ]);
      if (pRes.ok) {
        bar.policyState = await pRes.json();
      }
      if (aRes.ok) {
        const { approvals = [] } = await aRes.json();
        const box = document.getElementById("approvalsList");
        box.innerHTML = approvals.length === 0
          ? '<span class="item-meta">No pending approvals. Blue-team policy active.</span>'
          : "";
        for (const ap of approvals) {
          const row = document.createElement("div");
          row.className = "item";
          const info = document.createElement("div");
          const title = document.createElement("strong");
          title.textContent = `${ap.action} (${ap.action_class})`;
          const meta = document.createElement("div");
          meta.className = "item-meta";
          meta.textContent = `${ap.actor} · ${ap.summary}`;
          info.append(title, meta);

          const actions = document.createElement("div");
          actions.style.display = "flex";
          actions.style.gap = "8px";
          const btnApprove = document.createElement("button");
          btnApprove.className = "btn primary";
          btnApprove.textContent = "Approve";
          btnApprove.onclick = () => resolveApproval(ap.approval_id, "approve");
          const btnDeny = document.createElement("button");
          btnDeny.className = "btn danger";
          btnDeny.textContent = "Deny";
          btnDeny.onclick = () => resolveApproval(ap.approval_id, "deny");
          actions.append(btnApprove, btnDeny);
          row.append(info, actions);
          box.appendChild(row);
        }
      }
      if (cRes.ok) {
        const { capabilities = [] } = await cRes.json();
        const box = document.getElementById("capsList");
        box.innerHTML = capabilities.length === 0
          ? '<span class="item-meta">No capabilities registered yet.</span>'
          : "";
        for (const cap of capabilities) {
          const row = document.createElement("div");
          row.className = "item";
          const left = document.createElement("div");
          const t = document.createElement("strong");
          t.textContent = cap.capability;
          const m = document.createElement("div");
          m.className = "item-meta";
          m.textContent = `${cap.app} (${cap.action_class}) · ${cap.status}${cap.unavailable_reason ? " — " + cap.unavailable_reason : ""}`;
          left.append(t, m);
          row.appendChild(left);
          box.appendChild(row);
        }
      }
      if (sRes.ok) {
        const services = await sRes.json();
        modal.availableApps = services.map((s) => s.name);
        const box = document.getElementById("servicesList");
        box.innerHTML = services.length === 0
          ? '<span class="item-meta">No services registered.</span>'
          : "";
        for (const svc of services) {
          const row = document.createElement("div");
          row.className = "item";
          const left = document.createElement("div");
          const t = document.createElement("strong");
          t.textContent = svc.name;
          const m = document.createElement("div");
          m.className = "item-meta";
          m.textContent = `${svc.host}:${svc.port} · priority ${svc.priority} · ${svc.status || "unknown"}`;
          left.append(t, m);
          row.appendChild(left);
          box.appendChild(row);
        }
      }
    }

    async function resolveApproval(id, verb) {
      const r = await fetch(`/approvals/${encodeURIComponent(id)}/${verb}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ totp_code: totpInput.value.trim() })
      });
      const data = await r.json();
      if (!r.ok) {
        showToast(data.detail || "Step-up TOTP verification required");
        return;
      }
      showToast(`Approval ${id} marked ${data.status}`);
      totpInput.value = "";
      refreshAll();
    }

    bar.addEventListener("ecosystem-manage-restrictions", () => modal.open());
    bar.addEventListener("ecosystem-restore-restrictions", async () => {
      await fetch("/policy/restrictions/on", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
      showToast("Conservative Restrictions: On restored");
      refreshAll();
    });
    bar.addEventListener("ecosystem-freeze-request", async () => {
      await fetch("/policy/freeze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ initiated_by: "hub-ui", channel: "hub_ui", reason: "Emergency Freeze triggered from Hub UI" })
      });
      showToast("Ecosystem Freeze engaged");
      refreshAll();
    });
    bar.addEventListener("ecosystem-resume-request", async () => {
      const r = await fetch("/policy/resume", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ totp_code: totpInput.value.trim(), reason: "Operator resumed from Hub UI" })
      });
      const data = await r.json();
      if (!r.ok) {
        showToast(data.detail || "Enter 6-digit TOTP code in top bar to Resume");
        return;
      }
      totpInput.value = "";
      showToast("Normal policy operation resumed");
      refreshAll();
    });
    modal.addEventListener("ecosystem-override-submit", async (ev) => {
      const d = ev.detail;
      const r = await fetch("/policy/restrictions/off", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scope: d.scope,
          duration: d.duration,
          until_revoked: d.untilRevoked,
          reason: d.reason,
          totp_code: d.stepUpCredential
        })
      });
      const data = await r.json();
      if (!r.ok) {
        showToast(data.detail || "Failed to activate scoped override");
        return;
      }
      showToast("Signed scoped Restrictions: Off grant active");
      refreshAll();
    });

    document.getElementById("btnEnrollTotp").addEventListener("click", async () => {
      const r = await fetch("/auth/step-up/totp/enroll", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ operator_id: "admin", totp_code: totpInput.value.trim() })
      });
      const data = await r.json();
      if (!r.ok) {
        showToast(data.detail || "2FA already enrolled (enter current TOTP code to rotate)");
        return;
      }
      showToast(`TOTP Secret enrolled: ${data.secret} (${data.otpauth_uri})`);
    });

    refreshAll();
    setInterval(refreshAll, 5000);
  </script>
</body>
</html>
"""


@router.get("/ui", response_class=HTMLResponse)
async def serve_control_plane_ui():
    """Serve the Apple HIG Ecosystem Control Plane Dashboard."""
    return HTMLResponse(content=CONTROL_PLANE_HTML)
