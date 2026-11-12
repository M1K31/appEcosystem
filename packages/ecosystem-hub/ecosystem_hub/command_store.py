"""Hub-side SQLite record of every dispatched command and its audit trail.

A record is created once per (requester, idempotency key). Once it reaches a
final status it never changes again, with one exception: a command whose
outcome is unknown (the provider stopped answering after the envelope was
sent) may be reopened so the same idempotency key can ask the provider what
happened.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from .command_common import FINAL_STATUSES

_JSON_COLUMNS = {
    "actor": "actor_json",
    "target": "target_json",
    "parameters": "parameters_json",
    "decision": "decision_json",
    "result": "result_json",
}


class IdempotencyConflict(Exception):
    """The idempotency key was already used by this requester for a different request."""


class CommandStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS commands (
                    command_id TEXT PRIMARY KEY,
                    requester_app TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    capability TEXT NOT NULL,
                    action_class TEXT NOT NULL,
                    actor_json TEXT NOT NULL,
                    target_json TEXT NOT NULL,
                    parameters_json TEXT NOT NULL,
                    rationale TEXT,
                    correlation_id TEXT NOT NULL,
                    digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    provider_app TEXT,
                    decision_json TEXT,
                    approval_id TEXT,
                    result_json TEXT,
                    error TEXT,
                    outcome_unknown INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    UNIQUE (requester_app, idempotency_key)
                );
                CREATE INDEX IF NOT EXISTS idx_commands_correlation ON commands (correlation_id);
                CREATE INDEX IF NOT EXISTS idx_commands_approval ON commands (approval_id);
                CREATE TABLE IF NOT EXISTS command_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    command_id TEXT NOT NULL,
                    ts REAL NOT NULL,
                    event TEXT NOT NULL,
                    detail_json TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_command_events_command ON command_events (command_id, seq);
                """
            )

    # ---- row helpers -------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        def _load(col: str, default: Any) -> Any:
            raw = row[col]
            return json.loads(raw) if raw else default

        return {
            "command_id": row["command_id"],
            "requester_app": row["requester_app"],
            "idempotency_key": row["idempotency_key"],
            "capability": row["capability"],
            "action_class": row["action_class"],
            "actor": _load("actor_json", {}),
            "target": _load("target_json", {}),
            "parameters": _load("parameters_json", {}),
            "rationale": row["rationale"],
            "correlation_id": row["correlation_id"],
            "digest": row["digest"],
            "status": row["status"],
            "provider_app": row["provider_app"],
            "decision": _load("decision_json", None),
            "approval_id": row["approval_id"],
            "result": _load("result_json", None),
            "error": row["error"],
            "outcome_unknown": bool(row["outcome_unknown"]),
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
        }

    @staticmethod
    def _add_event(conn: sqlite3.Connection, command_id: str, ts: float, event: str,
                   detail: dict[str, Any] | None) -> None:
        conn.execute(
            "INSERT INTO command_events (command_id, ts, event, detail_json) VALUES (?, ?, ?, ?)",
            (command_id, ts, event, json.dumps(detail) if detail is not None else None),
        )

    def _events(self, conn: sqlite3.Connection, command_id: str) -> list[dict[str, Any]]:
        rows = conn.execute(
            "SELECT ts, event, detail_json FROM command_events WHERE command_id = ? ORDER BY seq",
            (command_id,),
        ).fetchall()
        return [
            {
                "ts": float(r["ts"]),
                "event": r["event"],
                "detail": json.loads(r["detail_json"]) if r["detail_json"] else None,
            }
            for r in rows
        ]

    # ---- public API --------------------------------------------------------

    def create(
        self,
        *,
        command_id: str,
        requester_app: str,
        idempotency_key: str,
        capability: str,
        action_class: str,
        actor: dict[str, Any],
        target: dict[str, Any],
        parameters: dict[str, Any],
        rationale: str | None,
        correlation_id: str,
        digest: str,
        detail: dict[str, Any] | None = None,
        now: float | None = None,
    ) -> tuple[dict[str, Any], bool]:
        """Create the record, or return the existing one for this requester and key.

        Raises IdempotencyConflict when the key was already used for a different request.
        """
        ts = time.time() if now is None else float(now)
        with self._lock, self._connect() as conn:
            existing = conn.execute(
                "SELECT * FROM commands WHERE requester_app = ? AND idempotency_key = ?",
                (requester_app, idempotency_key),
            ).fetchone()
            if existing is not None:
                if existing["digest"] != digest:
                    raise IdempotencyConflict(
                        f"idempotency_key '{idempotency_key}' was already used for a different request"
                    )
                rec = self._row_to_dict(existing)
                rec["events"] = self._events(conn, rec["command_id"])
                return rec, False
            conn.execute(
                """
                INSERT INTO commands (
                    command_id, requester_app, idempotency_key, capability, action_class,
                    actor_json, target_json, parameters_json, rationale, correlation_id,
                    digest, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'received', ?, ?)
                """,
                (
                    command_id, requester_app, idempotency_key, capability, action_class,
                    json.dumps(actor), json.dumps(target), json.dumps(parameters), rationale,
                    correlation_id, digest, ts, ts,
                ),
            )
            self._add_event(conn, command_id, ts, "created", detail)
            row = conn.execute("SELECT * FROM commands WHERE command_id = ?", (command_id,)).fetchone()
            rec = self._row_to_dict(row)
            rec["events"] = self._events(conn, command_id)
            return rec, True

    def get(self, command_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM commands WHERE command_id = ?", (command_id,)).fetchone()
            if row is None:
                return None
            rec = self._row_to_dict(row)
            rec["events"] = self._events(conn, command_id)
            return rec

    def get_by_approval(self, approval_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT command_id FROM commands WHERE approval_id = ? ORDER BY created_at LIMIT 1",
                (approval_id,),
            ).fetchone()
        return self.get(row["command_id"]) if row is not None else None

    def list(
        self,
        *,
        correlation_id: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        args: list[Any] = []
        if correlation_id:
            clauses.append("correlation_id = ?")
            args.append(correlation_id)
        if status:
            clauses.append("status = ?")
            args.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        args.append(max(1, min(int(limit), 1000)))
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM commands {where} ORDER BY created_at DESC, command_id DESC LIMIT ?",
                args,
            ).fetchall()
            return [self._row_to_dict(r) for r in rows]

    def update(
        self,
        command_id: str,
        *,
        status: str | None = None,
        provider_app: str | None = None,
        decision: dict[str, Any] | None = None,
        approval_id: str | None = None,
        result: dict[str, Any] | None = None,
        error: str | None = None,
        outcome_unknown: bool | None = None,
        event: str | None = None,
        detail: dict[str, Any] | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Change an open record. A record in a final status only accepts audit events."""
        ts = time.time() if now is None else float(now)
        sets: list[str] = []
        args: list[Any] = []
        for column, value in (
            ("status", status),
            ("provider_app", provider_app),
            ("approval_id", approval_id),
            ("error", error),
        ):
            if value is not None:
                sets.append(f"{column} = ?")
                args.append(value)
        if decision is not None:
            sets.append("decision_json = ?")
            args.append(json.dumps(decision))
        if result is not None:
            sets.append("result_json = ?")
            args.append(json.dumps(result))
        if outcome_unknown is not None:
            sets.append("outcome_unknown = ?")
            args.append(1 if outcome_unknown else 0)

        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT status FROM commands WHERE command_id = ?", (command_id,)).fetchone()
            if row is None:
                raise KeyError(f"Command '{command_id}' not found")
            if sets:
                if row["status"] in FINAL_STATUSES:
                    raise ValueError(f"Command '{command_id}' is already '{row['status']}' and cannot change")
                sets.append("updated_at = ?")
                args.append(ts)
                conn.execute(f"UPDATE commands SET {', '.join(sets)} WHERE command_id = ?", (*args, command_id))
            if event:
                self._add_event(conn, command_id, ts, event, detail)
            out = self._row_to_dict(
                conn.execute("SELECT * FROM commands WHERE command_id = ?", (command_id,)).fetchone()
            )
            out["events"] = self._events(conn, command_id)
            return out

    def claim(self, command_id: str, *, from_status: str, to_status: str = "dispatching",
              now: float | None = None) -> bool:
        """Atomically move a record from one status to another; False when someone else got there first."""
        ts = time.time() if now is None else float(now)
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "UPDATE commands SET status = ?, updated_at = ? WHERE command_id = ? AND status = ?",
                (to_status, ts, command_id, from_status),
            )
            if cur.rowcount == 1:
                self._add_event(conn, command_id, ts, "claimed", {"from": from_status, "to": to_status})
                return True
            return False

    def reopen_unknown(self, command_id: str, *, now: float | None = None) -> bool:
        """Reopen a failed command whose outcome is unknown so the provider can be asked again."""
        ts = time.time() if now is None else float(now)
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE commands SET status = 'dispatching', outcome_unknown = 0, error = NULL, updated_at = ?
                WHERE command_id = ? AND status = 'failed' AND outcome_unknown = 1
                """,
                (ts, command_id),
            )
            if cur.rowcount == 1:
                self._add_event(conn, command_id, ts, "reopened_unknown_outcome", None)
                return True
            return False

    def recover_interrupted(self, *, now: float | None = None) -> int:
        """Mark every command that was mid-dispatch at shutdown as failed with an unknown outcome."""
        ts = time.time() if now is None else float(now)
        with self._lock, self._connect() as conn:
            ids = [
                r["command_id"]
                for r in conn.execute("SELECT command_id FROM commands WHERE status = 'dispatching'").fetchall()
            ]
            for cid in ids:
                conn.execute(
                    """
                    UPDATE commands SET status = 'failed', outcome_unknown = 1,
                        error = 'hub restarted while the command was being dispatched', updated_at = ?
                    WHERE command_id = ?
                    """,
                    (ts, cid),
                )
                self._add_event(conn, cid, ts, "interrupted_by_restart", None)
            return len(ids)
