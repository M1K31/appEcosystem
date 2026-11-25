"""FastAPI routes for ECO-02 Cryptographic Node Auto-Pairing."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request

from ecosystem_auth.tokens import get_ecosystem_secret

from .policy_routes import _resolve_step_up_claims, get_policy_engine, get_step_up

router = APIRouter(prefix="/pairing", tags=["node-pairing"])


def get_pairing_manager(request: Request):
    mgr = getattr(request.app.state, "pairing_manager", None)
    if mgr is None:
        raise HTTPException(status_code=503, detail="Node pairing manager not initialized")
    return mgr


@router.get("/identity")
async def get_hub_pairing_identity(mgr=Depends(get_pairing_manager)):
    """Return the hub's ECDSA P-256 public key and SHA-256 fingerprint."""
    return {
        "hub_public_key_pem": mgr.hub_public_key_pem,
        "hub_fingerprint": mgr.hub_fingerprint,
    }


def _validate_step_up_fields(payload: dict[str, Any]) -> None:
    for field in ("step_up_token", "totp_code", "step_up_credential", "operator_id"):
        val = payload.get(field)
        if val is not None and not isinstance(val, str):
            raise HTTPException(status_code=400, detail=f"{field} must be a string")


@router.post("/request")
async def request_node_pairing(
    payload: dict[str, Any] = Body(...),
    mgr=Depends(get_pairing_manager),
):
    """Submit a pairing request from a joining LAN node."""
    raw_ttl = payload.get("ttl_seconds", 300)
    if isinstance(raw_ttl, bool) or not isinstance(raw_ttl, int):
        raise HTTPException(status_code=400, detail="ttl_seconds must be an integer")
    try:
        return mgr.request_pairing(
            node_id=str(payload.get("node_id") or ""),
            public_key_pem=str(payload.get("public_key_pem") or ""),
            hostname=str(payload.get("hostname") or ""),
            roles=payload.get("roles") if isinstance(payload.get("roles"), list) else None,
            ttl_seconds=raw_ttl,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=429, detail=str(exc))


@router.get("/pending")
async def list_pending_pairings(mgr=Depends(get_pairing_manager)):
    """List active pending pairing requests with fingerprints and 6-digit SAS codes."""
    return {"pending": mgr.list_pending()}


@router.get("/nodes")
async def list_paired_nodes(mgr=Depends(get_pairing_manager)):
    """List pinned / paired LAN nodes."""
    return {"nodes": mgr.list_paired_nodes()}


@router.post("/{pairing_id}/approve")
async def approve_node_pairing(
    pairing_id: str,
    request: Request,
    payload: dict[str, Any] = Body(...),
    mgr=Depends(get_pairing_manager),
    policy=Depends(get_policy_engine),
    step_up=Depends(get_step_up),
):
    """Pin a joining node's ECDSA public key and encrypt the shared secret for pickup.

    Refused while PolicyEngine is frozen; requires operator step-up auth
    (TOTP / Passkey) and interactive SAS or fingerprint confirmation.
    """
    if policy.export_state().get("frozen"):
        raise HTTPException(status_code=423, detail="Cannot approve node pairing while Ecosystem Freeze is active")

    _validate_step_up_fields(payload)
    claims = _resolve_step_up_claims(step_up, payload, request)
    try:
        secret_value = get_ecosystem_secret()
    except Exception:
        raise HTTPException(status_code=503, detail="Ecosystem HMAC secret not provisioned on hub")

    try:
        return mgr.approve_pairing(
            pairing_id,
            secret_value=secret_value,
            approved_by=str(claims.get("sub") or "admin"),
            expected_sas=payload.get("expected_sas"),
            expected_fingerprint=payload.get("expected_fingerprint"),
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))


@router.post("/{pairing_id}/reject")
async def reject_node_pairing(
    pairing_id: str,
    request: Request,
    payload: dict[str, Any] = Body(default={}),
    mgr=Depends(get_pairing_manager),
    step_up=Depends(get_step_up),
):
    _validate_step_up_fields(payload)
    _resolve_step_up_claims(step_up, payload, request)
    if not mgr.reject_pairing(pairing_id):
        raise HTTPException(status_code=404, detail="Pairing request not found")
    return {"pairing_id": pairing_id, "status": "rejected"}


@router.post("/{pairing_id}/claim")
async def claim_node_pairing(
    pairing_id: str,
    payload: dict[str, Any] = Body(...),
    mgr=Depends(get_pairing_manager),
):
    """One-time pickup of the ECDH+AES-256-GCM encrypted secret by the joining node."""
    try:
        return mgr.claim_pairing(
            pairing_id,
            node_id=str(payload.get("node_id") or ""),
            signature_b64=str(payload.get("signature") or ""),
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))


@router.delete("/nodes/{node_id}")
async def revoke_paired_node(
    node_id: str,
    request: Request,
    payload: dict[str, Any] = Body(default={}),
    mgr=Depends(get_pairing_manager),
    step_up=Depends(get_step_up),
):
    _validate_step_up_fields(payload)
    _resolve_step_up_claims(step_up, payload, request)
    removed = mgr.revoke_node_details(node_id)
    if removed is None:
        raise HTTPException(status_code=404, detail="Paired node not found")
    was_claimed = bool(removed.get("claimed_at"))
    return {
        "node_id": node_id,
        "status": "revoked",
        "pin_removed": True,
        "secret_rotation_required": was_claimed,
        "note": (
            "Node already claimed the shared ecosystem HMAC secret; rotate it "
            "(`ecosystem secret generate`) and re-pair remaining trusted nodes."
            if was_claimed
            else "Node pin removed and unclaimed pairing bundle invalidated before secret delivery."
        ),
    }
