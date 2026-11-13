"""Hub Unified Approval Service (`F10` consolidation) with async containment TTL revert & notifications."""
from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from typing import Any

from ecosystem_client.contracts import build_notification_envelope

logger = logging.getLogger(__name__)


def _ensure_policy_pkg() -> None:
    policy_pkg = Path(__file__).resolve().parent.parent / "packages" / "ecosystem-policy"
    if policy_pkg.is_dir() and str(policy_pkg) not in sys.path:
        sys.path.insert(0, str(policy_pkg))


class ApprovalService:
    """Hub-hosted approval manager wrapping `LocalApprovalQueue` + background TTL sweeper."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        step_up: Any,
        policy_engine: Any,
        notification_router: Any = None,
        event_bus: Any = None,
        sweep_interval_seconds: float = 15.0,
    ):
        _ensure_policy_pkg()
        from ecosystem_policy.approval_queue import LocalApprovalQueue

        self.step_up = step_up
        self.policy_engine = policy_engine
        self.notification_router = notification_router
        self.event_bus = event_bus
        self._sweep_interval = max(1.0, float(sweep_interval_seconds))
        self._reverted_events: list[dict[str, Any]] = []
        self.queue = LocalApprovalQueue(
            db_path=db_path,
            step_up=step_up,
            revert_callback=self._on_containment_revert,
        )
        self._task: asyncio.Task[None] | None = None
        self._running = False
        # Called with each approval record that expires, so whatever was waiting
        # on it (a stored command) learns that it will not run.
        self.on_expired: Any = None

    def _on_containment_revert(self, approval_record: dict[str, Any]) -> None:
        """Record revert execution and schedule peer notification on the running event loop."""
        self._reverted_events.append(dict(approval_record))
        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                loop.create_task(self._broadcast_revert(approval_record))
        except RuntimeError:
            pass

    async def _broadcast_revert(self, approval_record: dict[str, Any]) -> None:
        if self.event_bus is not None:
            try:
                from events.schemas import EventEnvelope

                await self.event_bus.publish(
                    EventEnvelope(
                        type="containment.reverted",
                        source="registry",
                        data={
                            "approval_id": approval_record["approval_id"],
                            "requester_service": approval_record["requester_service"],
                            "revert_plan": approval_record.get("revert_plan"),
                            "status": approval_record["status"],
                        },
                    )
                )
            except Exception as exc:
                logger.debug("Failed publishing containment.reverted event: %r", exc)

        if self.notification_router is not None:
            try:
                env = build_notification_envelope(
                    "notify.security",
                    "registry",
                    "medium",
                    f"Containment Reverted: {approval_record['action']}",
                    f"Approval {approval_record['approval_id']} ended as {approval_record['status']}; revert plan triggered.",
                    dedupe_key=f"approval:revert:{approval_record['approval_id']}",
                    privacy="redacted",
                )
                await self.notification_router.route(env)
            except Exception as exc:
                logger.debug("Failed routing revert notification: %r", exc)

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._sweep_loop())

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _sweep_loop(self) -> None:
        while self._running:
            try:
                self.expire_due()
            except Exception as exc:
                logger.debug("ApprovalService sweep error: %r", exc)
            await asyncio.sleep(self._sweep_interval)

    async def create_request(self, payload: dict[str, Any]) -> dict[str, Any]:
        rec = self.queue.request_approval(
            requester_service=str(payload.get("requester_service") or payload.get("app") or "unknown"),
            actor=str(payload.get("actor") or payload.get("requester_service") or "unknown"),
            action=str(payload["action"]),
            action_class=str(payload["action_class"]),
            target=payload.get("target") or {},
            summary=str(payload.get("summary") or ""),
            policy_version=int(payload.get("policy_version") or self.policy_engine.policy_version),
            mode=str(payload.get("mode") or self.policy_engine.mode),
            ttl_seconds=payload.get("ttl_seconds", 3600),
            async_containment=bool(payload.get("async_containment", False)),
            on_deny=str(payload.get("on_deny") or ("revert" if payload.get("async_containment") else "abort")),
            revert_plan=payload.get("revert_plan"),
            approval_id=payload.get("approval_id"),
        )
        if self.notification_router is not None:
            try:
                env = build_notification_envelope(
                    "notify.approval",
                    rec["requester_service"],
                    "high" if rec["action_class"] in ("contain", "remediate", "data_release") else "medium",
                    f"Approval Required: {rec['action']}",
                    rec["summary"],
                    dedupe_key=f"approval:req:{rec['approval_id']}",
                    actions=[
                        {"id": "approve", "label": "Approve", "requires": "approver_auth"},
                        {"id": "deny", "label": "Deny", "requires": "approver_auth"},
                        {"id": "freeze", "label": "Freeze", "requires": "none"},
                    ],
                    privacy="redacted",
                )
                await self.notification_router.route(env)
            except Exception as exc:
                logger.debug("Failed routing approval request notification: %r", exc)
        return rec

    # Every read and write expires overdue approvals through expire_due() first,
    # so the listener hears about each expiry; the queue would otherwise expire
    # them itself, silently.

    def list_approvals(self, *, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        self.expire_due()
        return self.queue.list_approvals(status=status, limit=limit)

    def get(self, approval_id: str) -> dict[str, Any] | None:
        self.expire_due()
        return self.queue.get(approval_id)

    def expire_due(self, *, now: float | None = None) -> list[dict[str, Any]]:
        """Expire overdue approvals and tell the listener about each one."""
        expired = self.queue.expire_due(now=now) if now is not None else self.queue.expire_due()
        if self.on_expired is not None:
            for rec in expired:
                try:
                    self.on_expired(rec)
                except Exception as exc:
                    logger.warning("Approval expiry listener failed for %s: %r", rec.get("approval_id"), exc)
        return expired

    def approve(
        self,
        approval_id: str,
        *,
        step_up_token: str | None = None,
        note: str = "",
    ) -> dict[str, Any]:
        # Expire first, through the listener: the queue would otherwise expire
        # overdue records on its own, silently.
        self.expire_due()
        return self.queue.approve(
            approval_id,
            step_up_token=step_up_token,
            note=note,
            is_frozen_fn=lambda: bool(self.policy_engine.frozen),
        )

    def deny(
        self,
        approval_id: str,
        *,
        step_up_token: str | None = None,
        note: str = "",
    ) -> dict[str, Any]:
        self.expire_due()
        return self.queue.deny(
            approval_id,
            step_up_token=step_up_token,
            note=note,
        )

    @property
    def reverted_events(self) -> list[dict[str, Any]]:
        return list(self._reverted_events)

