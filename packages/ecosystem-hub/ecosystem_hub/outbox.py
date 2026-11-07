"""SQLite-backed offline notification & deferred payload outbox for standalone/disconnected nodes."""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import Any, Awaitable, Callable

from ecosystem_client.contracts import assert_valid_schema


def default_outbox_path(app_name: str) -> Path:
    safe = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in app_name) or "app"
    override = (os.environ.get("ECOSYSTEM_OUTBOX_DIR") or "").strip()
    if override:
        return Path(override) / f"outbox-{safe}.db"
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
        return base / "Ecosystem" / f"outbox-{safe}.db"
    return Path.home() / ".local" / "share" / "ecosystem" / f"outbox-{safe}.db"


class DurableOutbox:
    """Bounded SQLite WAL queue storing pending `notify.*` envelopes while the Hub is unreachable."""

    def __init__(self, db_path: str | Path, *, max_items: int = 1000):
        self.db_path = Path(db_path)
        self.max_items = max(10, int(max_items))
        self._lock = threading.RLock()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS notification_outbox (
                    id TEXT PRIMARY KEY,
                    dedupe_key TEXT NOT NULL,
                    envelope_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_outbox_status_created
                ON notification_outbox(status, created_at);
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_outbox_dedupe_pending
                ON notification_outbox(dedupe_key, status);
                """
            )
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass

    def enqueue(self, envelope: dict[str, Any]) -> bool:
        """Enqueue a NotificationEnvelope if no pending item shares its dedupe_key.

        Returns True if newly enqueued, False if deduplicated against a pending item.
        """
        assert_valid_schema(envelope, "notification-envelope.v1")
        nid = envelope["id"]
        dedupe_key = envelope["dedupe_key"]
        now = time.time()
        payload = json.dumps(envelope, separators=(",", ":"), sort_keys=True)

        with self._lock, self._connect() as conn:
            existing = conn.execute(
                "SELECT id FROM notification_outbox WHERE dedupe_key = ? AND status = 'pending' LIMIT 1",
                (dedupe_key,),
            ).fetchone()
            if existing is not None:
                return False

            conn.execute(
                """
                INSERT OR REPLACE INTO notification_outbox
                (id, dedupe_key, envelope_json, status, attempts, last_error, created_at, updated_at)
                VALUES (?, ?, ?, 'pending', 0, NULL, ?, ?)
                """,
                (nid, dedupe_key, payload, now, now),
            )
            self._prune(conn)
            return True

    def _prune(self, conn: sqlite3.Connection) -> None:
        total_row = conn.execute("SELECT COUNT(*) AS c FROM notification_outbox").fetchone()
        total = int(total_row["c"]) if total_row else 0
        if total <= self.max_items:
            return
        excess = total - self.max_items
        # Evict delivered items first, then oldest pending items to strictly cap disk usage.
        conn.execute(
            """
            DELETE FROM notification_outbox
            WHERE id IN (
                SELECT id FROM notification_outbox
                ORDER BY CASE WHEN status = 'delivered' THEN 0 ELSE 1 END, created_at ASC
                LIMIT ?
            )
            """,
            (excess,),
        )

    def pending(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT envelope_json FROM notification_outbox
                WHERE status = 'pending'
                ORDER BY created_at ASC
                LIMIT ?
                """,
                (int(limit),),
            ).fetchall()
        return [json.loads(r["envelope_json"]) for r in rows]

    def pending_count(self) -> int:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM notification_outbox WHERE status = 'pending'"
            ).fetchone()
            return int(row["c"]) if row else 0

    def mark_delivered(self, notification_id: str) -> None:
        now = time.time()
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE notification_outbox SET status = 'delivered', updated_at = ? WHERE id = ?",
                (now, notification_id),
            )

    def record_failure(self, notification_id: str, error: str) -> None:
        now = time.time()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE notification_outbox
                SET attempts = attempts + 1, last_error = ?, updated_at = ?
                WHERE id = ?
                """,
                (error[:500], now, notification_id),
            )

    async def flush(
        self,
        deliver_fn: Callable[[dict[str, Any]], Awaitable[bool]],
        *,
        batch_size: int = 50,
    ) -> dict[str, int]:
        """Deliver pending notifications via `deliver_fn`. Stops early on transport failure."""
        items = self.pending(limit=batch_size)
        delivered = 0
        failed = 0
        for env in items:
            nid = env["id"]
            try:
                ok = await deliver_fn(env)
            except Exception as exc:
                self.record_failure(nid, repr(exc))
                failed += 1
                break
            if ok:
                self.mark_delivered(nid)
                delivered += 1
            else:
                self.record_failure(nid, "delivery rejected or hub unreachable")
                failed += 1
                break
        return {"delivered": delivered, "failed": failed, "remaining": self.pending_count()}

