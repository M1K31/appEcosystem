"""HTTP routes for command dispatch: /commands/*.

Dispatching always needs a signed caller. There is no loopback exemption: an
unsigned process on this machine must not be able to start actions. Reading
the record follows the same loopback-or-signed rule as the approval list.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from fastapi import APIRouter, Body, HTTPException, Request, status

from ecosystem_client.contracts import load_schema, validate_against_schema
from ecosystem_hub.command_common import json_too_large
from ecosystem_hub.command_store import IdempotencyConflict

from .commands import CommandDispatcher, InvalidCommand

router = APIRouter(tags=["commands"])

DISPATCH_SCOPE = "commands:dispatch"
_CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
_ACTOR_TYPES = ("service", "automation", "voice_intent", "ai_proposal", "operator")
_MAX_KEY = 128
_MAX_RATIONALE = 2000


def get_command_dispatcher(request: Request) -> CommandDispatcher:
    dispatcher = getattr(request.app.state, "command_dispatcher", None)
    if dispatcher is None:
        raise HTTPException(status_code=503, detail="Command dispatcher not initialized")
    return dispatcher


async def _signed_caller(request: Request) -> dict[str, Any]:
    from .policy_routes import _optional_auth

    auth = await _optional_auth(request)
    if auth is None:
        raise HTTPException(status_code=401, detail="Dispatching a command requires a signed ecosystem request")
    return auth


async def _reader(request: Request) -> None:
    from .policy_routes import _optional_auth, _require_loopback_or_auth

    _require_loopback_or_auth(request, await _optional_auth(request))


def _invalid(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=detail)


def _is_owner(auth: dict[str, Any]) -> bool:
    return auth.get("owned_names") == ["*"]


def _text(value: Any, name: str, *, maximum: int, required: bool = False) -> Optional[str]:
    if value is None or value == "":
        if required:
            raise _invalid(f"'{name}' is required")
        return None
    if not isinstance(value, str) or len(value) > maximum:
        raise _invalid(f"'{name}' must be a string of at most {maximum} characters")
    return value


def _resolve_actor(request: Request, payload: dict[str, Any], auth: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Build the envelope actor and say how strongly the requester's identity is known."""
    from .app import require_name_owner
    from .policy_routes import _resolve_step_up_claims

    raw = payload.get("actor")
    if not isinstance(raw, dict):
        raise _invalid("'actor' must be an object naming the requesting app")
    app_name = _text(raw.get("app"), "actor.app", maximum=_MAX_KEY, required=True)
    actor_type = raw.get("type") or "service"
    if actor_type not in _ACTOR_TYPES:
        raise _invalid(f"'actor.type' must be one of {', '.join(_ACTOR_TYPES)}")
    actor_id = _text(raw.get("id"), "actor.id", maximum=_MAX_KEY) or app_name
    device_id = _text(raw.get("device_id"), "actor.device_id", maximum=_MAX_KEY) or "local-device"

    if _is_owner(auth):
        # Every first-party app signs with the one shared secret, so the app name is a
        # claim. It must at least be a service this hub knows.
        if request.app.state.registry.get(app_name) is None:
            raise _invalid(f"'{app_name}' is not a registered service")
        identity = "shared_secret"
    else:
        scopes = auth.get("scopes") or []
        if DISPATCH_SCOPE not in scopes and "*" not in scopes:
            raise HTTPException(status_code=403, detail=f"This app key lacks the '{DISPATCH_SCOPE}' scope")
        require_name_owner(app_name, auth)
        identity = "app_key"

    auth_method: Optional[str] = None
    if actor_type == "operator":
        # A person is acting. That is only believed with step-up authentication,
        # and the operator is whoever the step-up names.
        try:
            claims = _resolve_step_up_claims(request.app.state.step_up_auth, payload, request)
        except HTTPException:
            raise HTTPException(status_code=403, detail="An operator actor requires step-up authentication")
        actor_id = str(claims["sub"])
        auth_method = str(claims["amr"])

    return (
        {"id": actor_id, "type": actor_type, "app": app_name, "device_id": device_id, "auth_method": auth_method},
        identity,
    )


def _detail_view(request: Request, dispatcher: CommandDispatcher, record: dict[str, Any]) -> dict[str, Any]:
    out = dispatcher.public_view(record)
    out.update(
        {
            "action_class": record["action_class"],
            "requester_app": record["requester_app"],
            "actor": record["actor"],
            "target": record["target"],
            "parameters": record["parameters"],
            "rationale": record["rationale"],
            "digest": record["digest"],
            "created_at": record["created_at"],
            "updated_at": record["updated_at"],
            "events": record.get("events", []),
            "approval": None,
        }
    )
    if record.get("approval_id"):
        approvals = getattr(request.app.state, "approval_service", None)
        if approvals is not None:
            out["approval"] = approvals.get(record["approval_id"])
    return out


@router.post("/commands/dispatch")
async def dispatch_command(request: Request, payload: dict[str, Any] = Body(...)):
    """Ask the hub to run a capability. Every policy or provider outcome is a 200 with `status`."""
    auth = await _signed_caller(request)
    dispatcher = get_command_dispatcher(request)

    capability = payload.get("capability")
    if not isinstance(capability, str) or not _CAPABILITY_RE.match(capability):
        raise _invalid("'capability' must be a dotted capability id such as 'containment.block_ip'")
    target = payload.get("target")
    if not isinstance(target, dict):
        raise _invalid("'target' must be an object with a 'scope'")
    errors = validate_against_schema(target, load_schema("command-envelope.v1")["properties"]["target"])
    if errors:
        raise _invalid(f"invalid target: {errors[0]}")
    parameters = payload.get("parameters")
    if parameters is None:
        parameters = {}
    if not isinstance(parameters, dict):
        raise _invalid("'parameters' must be an object")
    idempotency_key = _text(payload.get("idempotency_key"), "idempotency_key", maximum=_MAX_KEY, required=True)
    rationale = _text(payload.get("rationale"), "rationale", maximum=_MAX_RATIONALE)
    correlation_id = _text(payload.get("correlation_id"), "correlation_id", maximum=_MAX_KEY)
    context = payload.get("context")
    if context is not None and not isinstance(context, dict):
        raise _invalid("'context' must be an object")

    actor, identity = _resolve_actor(request, payload, auth)

    try:
        return await dispatcher.dispatch(
            requester_app=actor["app"],
            identity=identity,
            capability=capability,
            target=target,
            parameters=parameters,
            actor=actor,
            rationale=rationale,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            context=context,
        )
    except InvalidCommand as exc:
        raise _invalid(str(exc))
    except IdempotencyConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@router.get("/commands")
async def list_commands(
    request: Request,
    correlation_id: Optional[str] = None,
    status_filter: Optional[str] = None,
    limit: int = 100,
):
    await _reader(request)
    dispatcher = get_command_dispatcher(request)
    wanted_status = request.query_params.get("status") or status_filter
    records = dispatcher.store.list(correlation_id=correlation_id, status=wanted_status, limit=limit)
    return {
        "commands": [
            {**dispatcher.public_view(r), "requester_app": r["requester_app"], "created_at": r["created_at"]}
            for r in records
        ]
    }


@router.get("/commands/{command_id}")
async def get_command(command_id: str, request: Request):
    await _reader(request)
    dispatcher = get_command_dispatcher(request)
    record = dispatcher.store.get(command_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Command '{command_id}' not found")
    return _detail_view(request, dispatcher, record)


@router.post("/commands/{command_id}/result")
async def report_command_result(command_id: str, request: Request, payload: dict[str, Any] = Body(...)):
    """A provider reports the outcome of a command it had only accepted."""
    from .app import require_name_owner

    auth = await _signed_caller(request)
    dispatcher = get_command_dispatcher(request)
    record = dispatcher.store.get(command_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Command '{command_id}' not found")
    require_name_owner(record.get("provider_app") or "", auth)

    outcome = payload.get("status")
    if outcome not in ("completed", "failed"):
        raise _invalid("'status' must be 'completed' or 'failed'")
    result = payload.get("result")
    if result is not None and (not isinstance(result, dict) or json_too_large(result)):
        raise _invalid("'result' must be an object of at most 64 KiB")
    error = _text(payload.get("error"), "error", maximum=_MAX_RATIONALE)

    # Only a command the provider accepted can be finished this way, and only once.
    if not dispatcher.store.claim(command_id, from_status="accepted", to_status="reporting"):
        raise HTTPException(status_code=409, detail=f"Command '{command_id}' is not waiting for a result")
    updated = dispatcher.store.update(
        command_id,
        status=outcome,
        result=result,
        error=error,
        event="result_reported",
        detail={"status": outcome},
    )
    return dispatcher.public_view(updated)
