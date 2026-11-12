"""Hub command dispatcher.

Turns "run this capability" into a signed CommandEnvelope delivered to the
provider, with the hub's policy decision in front and a durable record behind:

    resolve provider -> gate 1 (PolicyEngine) -> sign -> forward -> record

The caller learns `completed` only when the provider said so. If the provider
could not be reached, nothing is queued for later.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

import httpx

from ecosystem_auth.tokens import sign_request
from ecosystem_client.contracts import (
    SchemaValidationError,
    build_command_envelope,
    build_notification_envelope,
    validate_against_schema,
)
from ecosystem_client.ulid import generate_ulid
from ecosystem_hub.command_common import (
    TRIGGER_BY_ACTOR_TYPE,
    actor_string,
    json_too_large,
    policy_action,
    policy_target,
    request_digest,
)
from ecosystem_hub.command_store import CommandStore

logger = logging.getLogger(__name__)

PROVIDER_STATUSES = frozenset({"completed", "accepted", "failed", "denied"})
# The only context a caller may add to the policy evaluation. Anything that
# could grant something (an approved data release, a budget flag) is not here.
CALLER_CONTEXT_KEYS = ("incident_id", "profile")
# A caller may only declare a trigger that makes the evaluation stricter.
RESTRICTIVE_TRIGGERS = frozenset({"schedule", "automation"})
DEFAULT_COMMAND_PATH = "/ecosystem/commands"
DEFAULT_TIMEOUT_SECONDS = 30.0
MAX_ENVELOPE_TTL_SECONDS = 300.0


class InvalidCommand(ValueError):
    """The request cannot be dispatched as written; nothing was stored."""


class CommandDispatcher:
    def __init__(
        self,
        *,
        store: CommandStore,
        capability_registry: Any,
        service_registry: Any,
        policy_engine: Any,
        approval_service: Any,
        notification_router: Any = None,
        app_store: Any = None,
        secret_fn: Callable[[], str],
        client_factory: Callable[[], httpx.AsyncClient] | None = None,
        connect_timeout: float = 3.0,
    ):
        self.store = store
        self._caps = capability_registry
        self._services = service_registry
        self._engine = policy_engine
        self._approvals = approval_service
        self._notifications = notification_router
        self._app_store = app_store
        self._secret_fn = secret_fn
        self._client_factory = client_factory or (lambda: httpx.AsyncClient())
        self._connect_timeout = float(connect_timeout)

    # ---- views -------------------------------------------------------------

    @staticmethod
    def public_view(record: dict[str, Any]) -> dict[str, Any]:
        return {
            "command_id": record["command_id"],
            "status": record["status"],
            "capability": record["capability"],
            "provider": record.get("provider_app"),
            "decision": record.get("decision"),
            "approval_id": record.get("approval_id"),
            "result": record.get("result"),
            "error": record.get("error"),
            "outcome_unknown": bool(record.get("outcome_unknown")),
            "correlation_id": record["correlation_id"],
        }

    # ---- provider resolution -----------------------------------------------

    def _third_party_names(self) -> set[str]:
        if self._app_store is None:
            return set()
        try:
            return set(self._app_store.all_owned_names())
        except Exception:
            return set()

    def _select_provider(self, capability: str, target: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
        """Pick the provider record for `capability`, or explain why there is none.

        A provider named in `target.service` is used or nothing is; dispatch
        never falls through to a different app than the one asked for.
        """
        resolution = self._caps.resolve(capability)
        if not resolution.available:
            return None, resolution.unavailable_reason or f"No provider for '{capability}'"
        wanted = target.get("service")
        third_party = self._third_party_names()
        reasons: list[str] = []
        candidates: list[tuple[int, str, dict[str, Any]]] = []
        for record in resolution.providers:
            app = record["app"]
            if wanted and app != wanted:
                continue
            service = self._services.get(app)
            if service is None:
                reasons.append(f"'{app}' is not registered as a running service")
                continue
            if str(getattr(service.status, "value", service.status)) == "unhealthy":
                reasons.append(f"'{app}' is unhealthy")
                continue
            if app in third_party:
                reasons.append(f"'{app}' cannot verify hub-signed commands (third-party app key)")
                continue
            candidates.append((-int(service.priority or 0), app, record))
        if not candidates:
            if wanted and not reasons:
                return None, f"'{wanted}' does not provide '{capability}'"
            return None, "; ".join(reasons) or f"No provider for '{capability}'"
        candidates.sort(key=lambda c: (c[0], c[1]))
        return candidates[0][2], ""

    def _capability_record(self, capability: str, app: str) -> dict[str, Any] | None:
        for record in self._caps.list_capabilities(capability=capability, app=app, active_only=False):
            return record
        return None

    # ---- dispatch ----------------------------------------------------------

    async def dispatch(
        self,
        *,
        requester_app: str,
        identity: str,
        capability: str,
        target: dict[str, Any],
        parameters: dict[str, Any],
        actor: dict[str, Any],
        rationale: str | None,
        idempotency_key: str,
        correlation_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run one capability request to a final or waiting status. Raises IdempotencyConflict."""
        target = dict(target or {})
        parameters = dict(parameters or {})
        if actor.get("app") != requester_app:
            raise InvalidCommand("actor.app must be the requesting app")
        if json_too_large(parameters):
            raise InvalidCommand("parameters are larger than 64 KiB")
        provider, unavailable_reason = self._select_provider(capability, target)
        action_class = provider["action_class"] if provider else "unknown"
        inputs_schema = ((provider or {}).get("manifest") or {}).get("inputs_schema")
        if isinstance(inputs_schema, dict) and inputs_schema:
            errors = validate_against_schema(parameters, inputs_schema)
            if errors:
                raise InvalidCommand(f"parameters do not match the capability's inputs: {errors[0]}")

        command_id = generate_ulid()
        record, created = self.store.create(
            command_id=command_id,
            requester_app=requester_app,
            idempotency_key=idempotency_key,
            capability=capability,
            action_class=action_class,
            actor=actor,
            target=target,
            parameters=parameters,
            rationale=rationale,
            correlation_id=correlation_id or command_id,
            digest=request_digest(capability, target, parameters),
            detail={"identity": identity},
        )
        if not created:
            # Same key, same request. Only an unknown outcome is worth asking about again;
            # the provider answers it from its replay store without running anything twice.
            if record["status"] == "failed" and record["outcome_unknown"] and record.get("provider_app"):
                # Asking again is still dispatching: the policy is evaluated as it stands now.
                refusal = self._retry_refusal(record, context)
                if refusal:
                    return self.public_view(
                        self.store.update(record["command_id"], event="retry_refused", detail={"reason": refusal})
                    )
                if self.store.reopen_unknown(record["command_id"]):
                    ref = f"approval:{record['approval_id']}" if record.get("approval_id") else None
                    return self.public_view(await self._forward(self.store.get(record["command_id"]), ref))
            return self.public_view(self.store.get(record["command_id"]) or record)

        if provider is None:
            return self.public_view(
                self.store.update(
                    command_id, status="provider_unavailable", error=unavailable_reason, event="provider_unavailable"
                )
            )
        self.store.update(command_id, provider_app=provider["app"])

        decision = self._decide(record, action_class, context)
        if decision is None:
            return self.public_view(
                self.store.update(command_id, status="denied", error="policy evaluation failed", event="denied")
            )
        decision_dict = decision.to_dict()
        self.store.update(command_id, decision=decision_dict, event="decided", detail={"result": decision.result})

        if decision.result == "deny":
            return self.public_view(
                self.store.update(command_id, status="denied", error=decision.reason, event="denied")
            )

        authorization_ref: str | None = None
        if decision.result == "require_approval" or decision.async_approval:
            approval = await self._request_approval(record, action_class, decision)
            if approval is None:
                return self.public_view(
                    self.store.update(
                        command_id, status="failed", error="could not open the approval request", event="failed"
                    )
                )
            if decision.result == "require_approval":
                return self.public_view(
                    self.store.update(
                        command_id,
                        status="pending_approval",
                        approval_id=approval["approval_id"],
                        event="approval_requested",
                        detail={"approval_id": approval["approval_id"]},
                    )
                )
            # Provisional containment: act now, the approval decides whether it stays.
            self.store.update(
                command_id,
                approval_id=approval["approval_id"],
                event="approval_requested",
                detail={"approval_id": approval["approval_id"], "provisional": True},
            )
            authorization_ref = f"approval:{approval['approval_id']}"

        final = await self._forward(self.store.get(command_id), authorization_ref)
        if decision.result == "allow_and_notify" and not decision.async_approval:
            await self._notify(final, decision)
        return self.public_view(final)

    def _decide(self, record: dict[str, Any], action_class: str, context: dict[str, Any] | None):
        """Gate 1. Returns the PolicyDecision, or None when the engine could not decide (fail closed)."""
        actor = record["actor"]
        ctx: dict[str, Any] = {}
        for key in CALLER_CONTEXT_KEYS:
            if context and context.get(key) is not None:
                ctx[key] = context[key]
        trigger = TRIGGER_BY_ACTOR_TYPE.get(str(actor.get("type")), "service")
        if context and context.get("trigger") in RESTRICTIVE_TRIGGERS:
            trigger = context["trigger"]
        ctx.update({"trigger": trigger, "command_id": record["command_id"], "capability": record["capability"]})
        try:
            from ecosystem_policy.models import ActionRequest

            return self._engine.decide(
                ActionRequest(
                    actor=actor_string(actor),
                    action=policy_action(record["capability"], action_class),
                    action_class=action_class,
                    target=policy_target(record["target"], action_class, record["parameters"]),
                    context=ctx,
                    rationale=str(record.get("rationale") or ""),
                    authenticated=True,
                )
            )
        except Exception as exc:
            logger.error("Policy evaluation failed for %s: %r", record["capability"], exc)
            return None

    def _retry_refusal(self, record: dict[str, Any], context: dict[str, Any] | None) -> str | None:
        """Why a command with an unknown outcome may not be sent again, or None when it may."""
        decision = self._decide(record, record["action_class"], context)
        if decision is None:
            return "policy evaluation failed"
        if decision.result == "deny":
            return decision.reason
        if decision.result == "require_approval" or decision.async_approval:
            approval_id = record.get("approval_id")
            lookup = getattr(self._approvals, "get", None)
            approval = lookup(approval_id) if (approval_id and callable(lookup)) else None
            if not isinstance(approval, dict):
                return "the command has no valid approval"
            if approval.get("status") == "approved":
                return None
            if decision.async_approval and approval.get("status") == "pending" and approval.get("async_containment"):
                return None
            return f"the approval is '{approval.get('status')}'"
        return None

    async def _request_approval(self, record: dict[str, Any], action_class: str, decision: Any) -> dict[str, Any] | None:
        try:
            return await self._approvals.create_request(
                {
                    "requester_service": record["requester_app"],
                    "actor": actor_string(record["actor"]),
                    "action": record["capability"],
                    "action_class": action_class,
                    "target": {
                        **record["target"],
                        "command_id": record["command_id"],
                        "digest": record["digest"],
                    },
                    "summary": record.get("rationale") or f"{actor_string(record['actor'])}: {record['capability']}",
                    "policy_version": decision.policy_version,
                    "mode": decision.mode,
                    "ttl_seconds": decision.ttl_seconds or 3600,
                    "async_containment": bool(decision.async_approval),
                    "on_deny": decision.on_deny,
                    "revert_plan": decision.revert_plan,
                }
            )
        except Exception as exc:
            logger.error("Could not open approval for %s: %r", record["command_id"], exc)
            return None

    async def _notify(self, record: dict[str, Any], decision: Any) -> None:
        if self._notifications is None:
            return
        try:
            envelope = build_notification_envelope(
                "notify.command",
                record["requester_app"],
                "low",
                f"Action {record['status']}: {record['capability']}",
                decision.notice or f"{actor_string(record['actor'])} ran {record['capability']}",
                dedupe_key=f"command:{record['command_id']}",
                privacy="redacted",
            )
            await self._notifications.route(envelope)
        except Exception as exc:
            logger.debug("Could not route command notification: %r", exc)

    # ---- forwarding --------------------------------------------------------

    async def _forward(self, record: dict[str, Any], authorization_ref: str | None) -> dict[str, Any]:
        """Send the command to its provider and record the answer. Returns the stored record."""
        command_id = record["command_id"]
        if record["status"] != "dispatching" and not self.store.claim(command_id, from_status=record["status"]):
            # Someone else is already sending it.
            return self.store.get(command_id) or record

        provider_app = record.get("provider_app") or ""
        service = self._services.get(provider_app)
        if service is None:
            return self.store.update(
                command_id,
                status="provider_unavailable",
                error=f"'{provider_app}' is not registered as a running service",
                event="provider_unavailable",
            )
        secret = self._secret_fn() or ""
        if not secret:
            return self.store.update(
                command_id,
                status="failed",
                error="the hub has no ecosystem secret and cannot sign commands",
                event="failed",
            )

        cap = self._capability_record(record["capability"], provider_app)
        try:
            timeout = float(((cap or {}).get("manifest") or {}).get("timeout_seconds") or DEFAULT_TIMEOUT_SECONDS)
        except (TypeError, ValueError):
            timeout = DEFAULT_TIMEOUT_SECONDS
        timeout = max(1.0, timeout)

        try:
            envelope = build_command_envelope(
                record["capability"],
                record["action_class"],
                record["actor"],
                record["target"],
                secret,
                parameters=record["parameters"],
                ttl_seconds=min(timeout + 10.0, MAX_ENVELOPE_TTL_SECONDS),
                correlation_id=record["correlation_id"],
                idempotency_key=record["idempotency_key"],
                authorization_ref=authorization_ref,
                rationale=record.get("rationale"),
                command_id=command_id,
            )
        except (SchemaValidationError, ValueError) as exc:
            return self.store.update(command_id, status="failed", error=f"invalid command: {exc}", event="failed")

        path = service.metadata.get("command_path") if isinstance(service.metadata, dict) else None
        if not (isinstance(path, str) and path.startswith("/")):
            path = DEFAULT_COMMAND_PATH
        url = f"{service.base_url.rstrip('/')}{path}"
        headers = sign_request("POST", url, secret, body=envelope)
        self.store.update(command_id, event="forwarded", detail={"provider": provider_app, "url": url})

        try:
            async with self._client_factory() as client:
                resp = await client.post(
                    url,
                    json=envelope,
                    headers=headers,
                    timeout=httpx.Timeout(timeout + 5.0, connect=self._connect_timeout),
                )
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            # The connection was never made: the provider did not receive the command.
            return self.store.update(
                command_id,
                status="provider_unavailable",
                error=f"could not connect to '{provider_app}'",
                event="provider_unavailable",
                detail={"error": type(exc).__name__},
            )
        except httpx.HTTPError as exc:
            # Sent, but no answer. It may or may not have run.
            return self.store.update(
                command_id,
                status="failed",
                error=f"no answer from '{provider_app}' after the command was sent",
                outcome_unknown=True,
                event="outcome_unknown",
                detail={"error": type(exc).__name__},
            )

        return self._record_answer(command_id, provider_app, resp)

    def _record_answer(self, command_id: str, provider_app: str, resp: httpx.Response) -> dict[str, Any]:
        try:
            body = resp.json()
        except ValueError:
            body = None
        if not isinstance(body, dict):
            body = {}

        if resp.status_code == 200 and body.get("status") in PROVIDER_STATUSES:
            result = body.get("result")
            detail: dict[str, Any] = {"status": body["status"], "duplicate": bool(body.get("duplicate"))}
            if body.get("decision") is not None:
                detail["provider_decision"] = body["decision"]
            if result is not None and (not isinstance(result, dict) or json_too_large(result)):
                result = None
                detail["result_dropped"] = "not an object or larger than 64 KiB"
            error = body.get("error")
            return self.store.update(
                command_id,
                status=body["status"],
                result=result,
                error=str(error) if error else None,
                outcome_unknown=bool(body.get("outcome_unknown")),
                event="provider_answered",
                detail=detail,
            )

        if resp.status_code == 200:
            # A 200 that is not the contract: something ran, but what is unclear.
            return self.store.update(
                command_id,
                status="failed",
                error=f"'{provider_app}' answered outside the command contract",
                outcome_unknown=True,
                event="provider_answered",
                detail={"http_status": 200},
            )
        error = body.get("error") or body.get("detail")
        return self.store.update(
            command_id,
            status="failed",
            error=f"'{provider_app}' answered HTTP {resp.status_code}" + (f": {error}" if error else ""),
            outcome_unknown=bool(body.get("outcome_unknown")),
            event="provider_answered",
            detail={"http_status": resp.status_code},
        )
