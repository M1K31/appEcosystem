"""Unified SQLite approval queue (`F10` consolidation) with step-up auth & async containment TTL revert."""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Callable

from ecosystem_client.ulid import generate_ulid

from .step_up import StepUpAuthenticator

logger = logging.getLogger(__name__)

VALID_APPROVER_METHODS = ("totp", "passkey", "device_key")


def default_approval_db_path(app_name: str = "hub") -> Path:
    base = Path(os.environ.get("ECOSYSTEM_DATA_DIR") or (Path.home() / ".local" / "share" / "ecosystem"))
    safe = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in app_name)
    return base / f"approvals-{safe}.db"


class LocalApprovalQueue:
    """Durable SQLite WAL approval store usable in the Hub (`registry/approvals.py`) and standalone apps.

    Lifecycle:
      `pending -> approved | denied | expired`

    Containment Revert Invariant:
      When an approval has `on_deny == 'revert'` (such as async `contain` blocks/quarantines),
      both `deny()` and `expire_due()` automatically invoke any registered `revert_callback`
      with `(approval_record)` and record `reverted = 1`.
    """

    def __init__(
        self,
        db_path: str | Path | None = None,
        *,
        step_up: StepUpAuthenticator | None = None,
        revert_callback: Callable[[dict[str, Any]], Any] | None = None,
        approve_callback: Callable[[dict[str, Any]], Any] | None = None,
    ):
        self.db_path = Path(db_path) if db_path else default_approval_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.step_up = step_up
        self._revert_cb = revert_callback
        self._approve_cb = approve_callback
        self._lock = threading.RLock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS unified_approvals (
                    seq_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    approval_id TEXT NOT NULL UNIQUE,
                    requester_service TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    action_class TEXT NOT NULL,
                    target_json TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    policy_version INTEGER NOT NULL DEFAULT 3,
                    mode TEXT NOT NULL DEFAULT 'normal',
                    status TEXT NOT NULL DEFAULT 'pending',
                    async_containment INTEGER NOT NULL DEFAULT 0,
                    on_deny TEXT NOT NULL DEFAULT 'abort',
                    revert_plan_json TEXT,
                    reverted INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL,
                    expires_at REAL,
                    resolved_at REAL,
                    resolved_by TEXT,
                    auth_method TEXT,
                    resolution_note TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_unified_approvals_status ON unified_approvals(status, created_at)"
            )
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": int(row["seq_id"]),
            "approval_id": row["approval_id"],
            "requester_service": row["requester_service"],
            "actor": row["actor"],
            "action": row["action"],
            "action_class": row["action_class"],
            "target": json.loads(row["target_json"] or "{}"),
            "summary": row["summary"],
            "policy_version": int(row["policy_version"]),
            "mode": row["mode"],
            "status": row["status"],
            "async_containment": bool(row["async_containment"]),
            "on_deny": row["on_deny"],
            "revert_plan": json.loads(row["revert_plan_json"]) if row["revert_plan_json"] else None,
            "reverted": bool(row["reverted"]),
            "created_at": float(row["created_at"]),
            "expires_at": float(row["expires_at"]) if row["expires_at"] is not None else None,
            "resolved_at": float(row["resolved_at"]) if row["resolved_at"] is not None else None,
            "resolved_by": row["resolved_by"],
            "auth_method": row["auth_method"],
            "resolution_note": row["resolution_note"],
        }

    def request_approval(
        self,
        *,
        requester_service: str,
        actor: str,
        action: str,
        action_class: str,
        target: dict[str, Any] | None = None,
        summary: str = "",
        policy_version: int = 3,
        mode: str = "normal",
        ttl_seconds: int | None = 3600,
        async_containment: bool = False,
        on_deny: str = "abort",
        revert_plan: dict[str, Any] | None = None,
        approval_id: str | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        ts = time.time() if now is None else now
        aid = approval_id or generate_ulid(int(ts * 1000))
        exp = (ts + int(ttl_seconds)) if ttl_seconds else None
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO unified_approvals (
                    approval_id, requester_service, actor, action, action_class,
                    target_json, summary, policy_version, mode, status,
                    async_containment, on_deny, revert_plan_json, reverted,
                    created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, 0, ?, ?)
                """,
                (
                    aid,
                    requester_service,
                    actor,
                    action,
                    action_class,
                    json.dumps(target or {}, sort_keys=True),
                    summary or f"{actor} requested {action} ({action_class})",
                    int(policy_version),
                    mode,
                    1 if async_containment else 0,
                    on_deny,
                    json.dumps(revert_plan, sort_keys=True) if revert_plan else None,
                    ts,
                    exp,
                ),
            )
            row = conn.execute(
                "SELECT * FROM unified_approvals WHERE approval_id = ?", (aid,)
            ).fetchone()
            return self._row_to_dict(row)

    def get(self, approval_id_or_seq: str | int) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            if isinstance(approval_id_or_seq, int) or str(approval_id_or_seq).isdigit():
                row = conn.execute(
                    "SELECT * FROM unified_approvals WHERE seq_id = ? OR approval_id = ?",
                    (int(approval_id_or_seq), str(approval_id_or_seq)),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM unified_approvals WHERE approval_id = ?",
                    (str(approval_id_or_seq),),
                ).fetchone()
            return self._row_to_dict(row) if row else None

    def list_approvals(self, *, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        self.expire_due()
        with self._lock, self._connect() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM unified_approvals WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                    (status, max(1, int(limit))),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM unified_approvals ORDER BY created_at DESC LIMIT ?",
                    (max(1, int(limit))),
                ).fetchall()
            return [self._row_to_dict(r) for r in rows]

    def _authenticate_approver(
        self,
        *,
        step_up_token: str | None,
        resolved_by: str | None,
        auth_method: str | None,
        now: float,
    ) -> tuple[str, str]:
        if step_up_token and self.step_up is not None:
            claims = self.step_up.verify_step_up_token(step_up_token, now=now)
            if not claims:
                raise PermissionError("Invalid or expired step-up authentication token")
            return str(claims["sub"]), str(claims["amr"])
        if auth_method in VALID_APPROVER_METHODS and resolved_by:
            return str(resolved_by), str(auth_method)
        raise PermissionError(
            "Approvals require an authenticated step-up operator (totp, passkey, or device_key); shared/ambient displays cannot approve"
        )

    def approve(
        self,
        approval_id_or_seq: str | int,
        *,
        step_up_token: str | None = None,
        resolved_by: str | None = None,
        auth_method: str | None = None,
        note: str = "",
        is_frozen_fn: Callable[[], bool] | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        ts = time.time() if now is None else now
        operator, method = self._authenticate_approver(
            step_up_token=step_up_token,
            resolved_by=resolved_by,
            auth_method=auth_method,
            now=ts,
        )
        if is_frozen_fn is not None and is_frozen_fn():
            raise PermissionError("Cannot approve and dispatch actions while Ecosystem Freeze is active")

        self.expire_due(now=ts)
        rec = self.get(approval_id_or_seq)
        if rec is None:
            raise KeyError(f"Approval '{approval_id_or_seq}' not found")
        if rec["status"] != "pending":
            raise ValueError(f"Approval '{rec['approval_id']}' is already '{rec['status']}'")

        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE unified_approvals
                SET status = 'approved', resolved_at = ?, resolved_by = ?, auth_method = ?, resolution_note = ?
                WHERE approval_id = ? AND status = 'pending'
                """,
                (ts, operator, method, note, rec["approval_id"]),
            )
        updated = self.get(rec["approval_id"])
        assert updated is not None
        if self._approve_cb is not None and not updated["async_containment"]:
            try:
                self._approve_cb(updated)
            except Exception as exc:
                logger.warning("Approval execution callback failed for %s: %r", updated["approval_id"], exc)
        return updated

    def deny(
        self,
        approval_id_or_seq: str | int,
        *,
        step_up_token: str | None = None,
        resolved_by: str | None = None,
        auth_method: str | None = None,
        note: str = "",
        now: float | None = None,
    ) -> dict[str, Any]:
        ts = time.time() if now is None else now
        operator, method = self._authenticate_approver(
            step_up_token=step_up_token,
            resolved_by=resolved_by,
            auth_method=auth_method,
            now=ts,
        )
        rec = self.get(approval_id_or_seq)
        if rec is None:
            raise KeyError(f"Approval '{approval_id_or_seq}' not found")
        if rec["status"] != "pending":
            raise ValueError(f"Approval '{rec['approval_id']}' is already '{rec['status']}'")

        should_revert = rec["on_deny"] == "revert" or rec["async_containment"]
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE unified_approvals
                SET status = 'denied', reverted = ?, resolved_at = ?, resolved_by = ?, auth_method = ?, resolution_note = ?
                WHERE approval_id = ? AND status = 'pending'
                """,
                (1 if should_revert else 0, ts, operator, method, note, rec["approval_id"]),
            )
        updated = self.get(rec["approval_id"])
        assert updated is not None
        if should_revert and self._revert_cb is not None:
            try:
                self._revert_cb(updated)
            except Exception as exc:
                logger.error("Containment revert callback failed on deny for %s: %r", updated["approval_id"], exc)
        return updated

    def expire_due(self, *, now: float | None = None) -> list[dict[str, Any]]:
        """Expire pending approvals past `expires_at` and execute containment revert plans."""
        ts = time.time() if now is None else now
        expired_records: list[dict[str, Any]] = []
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM unified_approvals WHERE status = 'pending' AND expires_at IS NOT NULL AND expires_at <= ?",
                (ts,),
            ).fetchall()
            for row in rows:
                rec = self._row_to_dict(row)
                should_revert = rec["on_deny"] == "revert" or rec["async_containment"]
                conn.execute(
                    """
                    UPDATE unified_approvals
                    SET status = 'expired', reverted = ?, resolved_at = ?, resolution_note = 'TTL lease expired'
                    WHERE approval_id = ? AND status = 'pending'
                    """,
                    (1 if should_revert else 0, ts, rec["approval_id"]),
                )
                rec["status"] = "expired"
                rec["reverted"] = should_revert
                rec["resolved_at"] = ts
                expired_records.append(rec)

        if self._revert_cb is not None:
            for rec in expired_records:
                if rec["reverted"]:
                    try:
                        self._revert_cb(rec)
                    except Exception as exc:
                        logger.error("Containment revert callback failed on expiry for %s: %r", rec["approval_id"], exc)
        return expired_records

