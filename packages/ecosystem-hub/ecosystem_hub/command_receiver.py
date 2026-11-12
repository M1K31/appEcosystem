"""Provider side of command dispatch.

An app that offers capabilities creates one CommandReceiver, registers a
handler per capability, and mounts `build_command_router(receiver)`. For every
incoming CommandEnvelope the receiver:

1. verifies schema, signature and expiry;
2. checks the command is addressed to this app and registered here;
3. refuses an envelope whose action class differs from the registered one;
4. answers a repeated idempotency key from its replay store without running
   anything again;
5. evaluates the app's own PolicyEngine (the second gate);
6. for `require_approval`, confirms the approval with the hub;
7. runs the handler and reports `completed` only when it returns.

Nothing here trusts a field of the envelope to grant permission.
"""
from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

import httpx

from ecosystem_auth.tokens import sign_request
from ecosystem_client.contracts import verify_command_envelope

from .command_common import (
    TRIGGER_BY_ACTOR_TYPE,
    actor_string,
    json_too_large,
    policy_action,
    policy_target,
    request_digest,
)

logger = logging.getLogger(__name__)

ACTION_CLASSES = frozenset({"observe", "investigate", "contain", "remediate", "data_release", "system_change"})
REPLAY_RETENTION_SECONDS = 24 * 3600


@dataclass(frozen=True)
class CommandContext:
    """What a handler receives. Every field was verified before the handler runs."""

    command_id: str
    command: str
    action_class: str
    actor: dict[str, Any]
    target: dict[str, Any]
    parameters: dict[str, Any]
    rationale: str | None
    correlation_id: str
    authorization_ref: str | None


class CommandFailed(Exception):
    """Raised by a handler when the action definitely did not take effect."""

    def __init__(self, message: str, *, result: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.result = result


class Accepted:
    """Returned by a handler that started long-running work and will report the result later."""

    def __init__(self, job_ref: str):
        self.job_ref = str(job_ref)


Handler = Callable[[CommandContext], Awaitable["dict[str, Any] | Accepted"]]
ApprovalVerifier = Callable[[dict[str, Any]], Awaitable[bool]]


class _ReplayStore:
    """Remembers each (requester, idempotency key) and the answer it was given."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS received_commands (
                    requester TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    command_id TEXT NOT NULL UNIQUE,
                    digest TEXT NOT NULL,
                    response_json TEXT,
                    received_at REAL NOT NULL,
                    PRIMARY KEY (requester, idempotency_key)
                );
                """
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def begin(self, *, requester: str, key: str, command_id: str, digest: str, now: float) -> tuple[str, dict | None]:
        """Reserve the key. Returns ("new", None), ("duplicate", response), ("running", None) or ("conflict", None)."""
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM received_commands WHERE received_at < ?", (now - REPLAY_RETENTION_SECONDS,))
            row = conn.execute(
                "SELECT * FROM received_commands WHERE requester = ? AND idempotency_key = ?",
                (requester, key),
            ).fetchone()
            if row is not None:
                if row["digest"] != digest:
                    return "conflict", None
                if row["response_json"] is None:
                    return "running", None
                return "duplicate", json.loads(row["response_json"])
            if conn.execute("SELECT 1 FROM received_commands WHERE command_id = ?", (command_id,)).fetchone():
                return "conflict", None
            conn.execute(
                "INSERT INTO received_commands (requester, idempotency_key, command_id, digest, received_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (requester, key, command_id, digest, now),
            )
            return "new", None

    def finish(self, *, requester: str, key: str, response: dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE received_commands SET response_json = ? WHERE requester = ? AND idempotency_key = ?",
                (json.dumps(response), requester, key),
            )


class CommandReceiver:
    def __init__(
        self,
        app_name: str,
        *,
        secret: str,
        policy_engine: Any,
        replay_db_path: str | Path,
        approval_verifier: ApprovalVerifier | None = None,
        now_fn: Callable[[], float] = time.time,
    ):
        if not secret:
            raise ValueError("CommandReceiver needs the ecosystem secret to verify commands")
        if policy_engine is None:
            raise ValueError("CommandReceiver needs a PolicyEngine; commands are never run ungated")
        self.app_name = app_name
        self._secret = secret
        self._engine = policy_engine
        self._verifier = approval_verifier
        self._now = now_fn
        self._replay = _ReplayStore(replay_db_path)
        self._handlers: dict[str, tuple[str, Handler, float]] = {}

    def register(self, command: str, action_class: str, handler: Handler, *, timeout_seconds: float = 30.0) -> None:
        """Register the handler for one capability, with the action class this app advertises for it."""
        if action_class not in ACTION_CLASSES:
            raise ValueError(f"Unknown action class '{action_class}'")
        self._handlers[command] = (action_class, handler, float(timeout_seconds))

    @property
    def commands(self) -> list[str]:
        return sorted(self._handlers)

    @staticmethod
    def _body(command_id: str | None, status: str, *, result: Any = None, error: str | None = None,
              decision: dict[str, Any] | None = None, outcome_unknown: bool = False) -> dict[str, Any]:
        return {
            "command_id": command_id,
            "status": status,
            "result": result,
            "error": error,
            "decision": decision,
            "duplicate": False,
            "outcome_unknown": outcome_unknown,
        }

    async def handle(self, envelope: Any) -> tuple[int, dict[str, Any]]:
        """Process one incoming envelope. Returns (HTTP status, response body)."""
        # 1. Authenticity: schema, signature, expiry, no notification id as authorization.
        if not isinstance(envelope, dict):
            return 401, self._body(None, "failed", error="command envelope must be a JSON object")
        ok, why = verify_command_envelope(envelope, self._secret, now=self._now())
        if not ok:
            cid = envelope.get("id") if isinstance(envelope.get("id"), str) else None
            return 401, self._body(cid, "failed", error=why)

        command_id: str = envelope["id"]
        command: str = envelope["command"]
        actor: dict[str, Any] = envelope["actor"]
        target: dict[str, Any] = envelope["target"]
        parameters: dict[str, Any] = envelope["parameters"]

        # 2. Addressed to this app, and a capability it actually offers.
        addressed_to = target.get("service")
        if addressed_to not in (None, self.app_name):
            return 404, self._body(command_id, "failed", error=f"command is addressed to '{addressed_to}'")
        registered = self._handlers.get(command)
        if registered is None:
            return 404, self._body(command_id, "failed", error=f"'{self.app_name}' does not provide '{command}'")
        action_class, handler, timeout_seconds = registered

        # 3. The class is the one this app registered, never the one the envelope claims.
        if envelope["action_class"] != action_class:
            return 200, self._body(
                command_id, "denied",
                error=f"action class mismatch: '{command}' is '{action_class}', not '{envelope['action_class']}'",
            )

        # 4. Replay: the same key is answered from memory, never executed twice.
        requester = str(actor.get("app") or "unknown")
        key = str(envelope["idempotency_key"])
        state, stored = self._replay.begin(
            requester=requester,
            key=key,
            command_id=command_id,
            digest=request_digest(command, target, parameters),
            now=self._now(),
        )
        if state == "duplicate":
            assert stored is not None
            return 200, {**stored, "duplicate": True}
        if state == "running":
            return 409, self._body(
                command_id, "failed", error="a command with this idempotency key is still running",
                outcome_unknown=True,
            )
        if state == "conflict":
            return 409, self._body(
                command_id, "failed", error="idempotency key or command id was already used for a different request"
            )

        body = await self._decide_and_run(envelope, action_class, handler, timeout_seconds)
        self._replay.finish(requester=requester, key=key, response=body)
        return 200, body

    async def _decide_and_run(self, envelope: dict[str, Any], action_class: str, handler: Handler,
                              timeout_seconds: float) -> dict[str, Any]:
        command_id = envelope["id"]
        command = envelope["command"]
        actor = envelope["actor"]

        # 5. Second policy gate, with this app's own engine.
        try:
            from ecosystem_policy.models import ActionRequest

            decision = self._engine.decide(
                ActionRequest(
                    actor=actor_string(actor),
                    action=policy_action(command),
                    action_class=action_class,
                    target=policy_target(envelope["target"], action_class, envelope["parameters"]),
                    context={
                        "trigger": TRIGGER_BY_ACTOR_TYPE.get(str(actor.get("type")), "service"),
                        "command_id": command_id,
                        "capability": command,
                    },
                    rationale=str(envelope.get("rationale") or ""),
                    authenticated=True,
                )
            )
            decision_dict = decision.to_dict()
        except Exception as exc:  # fail closed
            logger.error("Policy evaluation failed for %s: %r", command, exc)
            return self._body(command_id, "denied", error="policy evaluation failed")

        if decision.result == "deny":
            return self._body(command_id, "denied", error=decision.reason, decision=decision_dict)

        # 6. An approval is confirmed with the hub, not read from the envelope.
        if decision.result == "require_approval":
            ref = envelope.get("authorization_ref")
            approved = False
            if isinstance(ref, str) and ref.startswith("approval:") and self._verifier is not None:
                try:
                    approved = bool(await self._verifier(envelope))
                except Exception as exc:
                    logger.warning("Approval verification failed for %s: %r", command_id, exc)
                    approved = False
            if not approved:
                return self._body(command_id, "denied", error="approval required", decision=decision_dict)

        # 7. Run. `completed` means the handler returned, i.e. it confirmed the action.
        ctx = CommandContext(
            command_id=command_id,
            command=command,
            action_class=action_class,
            actor=dict(actor),
            target=dict(envelope["target"]),
            parameters=dict(envelope["parameters"]),
            rationale=envelope.get("rationale"),
            correlation_id=str(envelope["correlation_id"]),
            authorization_ref=envelope.get("authorization_ref"),
        )
        try:
            outcome = await asyncio.wait_for(handler(ctx), timeout=timeout_seconds)
        except CommandFailed as exc:
            result = exc.result if isinstance(exc.result, dict) and not json_too_large(exc.result) else None
            return self._body(command_id, "failed", result=result, error=exc.message, decision=decision_dict)
        except asyncio.TimeoutError:
            return self._body(
                command_id, "failed", error=f"handler timed out after {timeout_seconds:g}s",
                decision=decision_dict, outcome_unknown=True,
            )
        except Exception as exc:
            # The message may hold paths or secrets; only the type crosses the wire.
            logger.exception("Handler for %s raised", command)
            return self._body(
                command_id, "failed", error=type(exc).__name__, decision=decision_dict, outcome_unknown=True
            )

        if isinstance(outcome, Accepted):
            return self._body(command_id, "accepted", result={"job_ref": outcome.job_ref}, decision=decision_dict)
        if not isinstance(outcome, dict):
            return self._body(
                command_id, "failed", error="handler returned no result object", decision=decision_dict,
                outcome_unknown=True,
            )
        # 8. Bounded result.
        if json_too_large(outcome):
            return self._body(command_id, "failed", error="result too large", decision=decision_dict)
        return self._body(command_id, "completed", result=outcome, decision=decision_dict)


def build_command_router(receiver: CommandReceiver):
    """A FastAPI router exposing `POST /ecosystem/commands` for this receiver."""
    from fastapi import APIRouter, Request
    from fastapi.responses import JSONResponse

    router = APIRouter()

    async def receive_command(request):
        try:
            envelope = await request.json()
        except Exception:
            envelope = None
        status_code, body = await receiver.handle(envelope)
        return JSONResponse(status_code=status_code, content=body)

    # FastAPI is imported lazily, so with postponed annotations the name
    # `Request` would not resolve; give FastAPI the class itself.
    receive_command.__annotations__ = {"request": Request}
    router.add_api_route("/ecosystem/commands", receive_command, methods=["POST"])
    return router


class HubApprovalVerifier:
    """Confirms with the hub that a command's approval is real and is for this execution.

    Every first-party app holds the shared secret, so a signed envelope that
    names an approval proves nothing by itself. The hub's own record does: the
    approval must belong to this exact request (digest, capability, action
    class, requester), be routed to this provider, and be in flight right now
    (`dispatching`), so an approval cannot be replayed after it was used or
    redirected to another provider. Any error, mismatch or unreachable hub is
    a refusal.
    """

    def __init__(
        self,
        registry_url: str,
        secret: str,
        *,
        app_name: str,
        client_factory: Callable[[], httpx.AsyncClient] | None = None,
        timeout: float = 3.0,
    ):
        self.registry_url = registry_url.rstrip("/")
        self.app_name = app_name
        self._secret = secret
        self._client_factory = client_factory or (lambda: httpx.AsyncClient(timeout=timeout))

    async def __call__(self, envelope: dict[str, Any]) -> bool:
        ref = envelope.get("authorization_ref")
        if not isinstance(ref, str) or not ref.startswith("approval:"):
            return False
        approval_id = ref[len("approval:"):]
        url = f"{self.registry_url}/commands/{envelope.get('id')}"
        try:
            headers = sign_request("GET", url, self._secret) if self._secret else {}
            async with self._client_factory() as client:
                resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                return False
            record = resp.json()
        except Exception as exc:
            logger.warning("Could not confirm approval %s with the hub: %r", approval_id, exc)
            return False
        if not isinstance(record, dict):
            return False
        expected = {
            "approval_id": approval_id,
            "digest": request_digest(envelope["command"], envelope["target"], envelope["parameters"]),
            "capability": envelope["command"],
            "action_class": envelope["action_class"],
            "requester_app": (envelope.get("actor") or {}).get("app"),
            "provider": self.app_name,
            "status": "dispatching",
        }
        for field, value in expected.items():
            if record.get(field) != value:
                return False
        approval = record.get("approval")
        if not isinstance(approval, dict):
            return False
        if approval.get("status") == "approved":
            return True
        return (
            envelope["action_class"] == "contain"
            and approval.get("status") == "pending"
            and bool(approval.get("async_containment"))
        )
