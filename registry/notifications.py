"""Cross-device notification router with global dedupe_key TTL, quiet hours, redaction, and federated mobile push."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import sqlite3
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Awaitable, Callable

import httpx

from ecosystem_auth.tokens import get_ecosystem_secret, sign_request
from ecosystem_client.contracts import assert_valid_schema

logger = logging.getLogger(__name__)

SEVERITY_RANK: dict[str, int] = {
    "low": 10,
    "medium": 20,
    "high": 30,
    "critical": 40,
}

_TTL_RE = re.compile(r"^([0-9]+)(s|m|h|d)$")
_SECRET_TOKEN_RE = re.compile(
    r"\b(ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,}|Bearer\s+[A-Za-z0-9._~+/-]+=*)"
)
_HOME_PATH_RE = re.compile(r"(/Users/[^/\s]+|/home/[^/\s]+|[A-Za-z]:\\Users\\[^\\\s]+)")


def parse_ttl_seconds(ttl: str) -> int:
    m = _TTL_RE.match((ttl or "24h").strip())
    if not m:
        return 86400
    amount = int(m.group(1))
    unit = m.group(2)
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    return max(1, min(amount * mult, 30 * 86400))


def redact_notification_text(text: str) -> str:
    """Scrub accidental tokens and local user home paths from redacted push copy."""
    if not text:
        return ""
    scrubbed = _SECRET_TOKEN_RE.sub("[REDACTED]", text)
    scrubbed = _HOME_PATH_RE.sub("~", scrubbed)
    return scrubbed


def is_in_quiet_hours(quiet_window: str | None, now_dt: datetime | None = None) -> bool:
    """Return True if `now_dt` (local wall time) falls inside `'HH:MM-HH:MM'`."""
    if not quiet_window:
        return False
    parts = quiet_window.strip().split("-")
    if len(parts) != 2:
        return False
    try:
        sh, sm = (int(x) for x in parts[0].split(":"))
        eh, em = (int(x) for x in parts[1].split(":"))
    except ValueError:
        return False

    start_min = sh * 60 + sm
    end_min = eh * 60 + em
    dt = now_dt or datetime.now()
    cur_min = dt.hour * 60 + dt.minute

    if start_min == end_min:
        return False
    if start_min < end_min:
        return start_min <= cur_min < end_min
    # Overnight wrap-around (e.g. 23:00-07:00)
    return cur_min >= start_min or cur_min < end_min


ChannelHandler = Callable[[dict[str, Any], dict[str, Any]], Awaitable[bool]]


class NotificationRouter:
    """Deduplicating, privacy-preserving notification router for the appEcosystem Hub."""

    def __init__(
        self,
        persistence_path: str | Path = "data/notifications.db",
        *,
        hmac_secret: str | None = None,
        channel_handlers: dict[str, ChannelHandler] | None = None,
        clock: Callable[[], datetime] | None = None,
        max_recent: int = 200,
    ):
        self.db_path = Path(persistence_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._hmac_secret = hmac_secret
        self._clock = clock or datetime.now
        self._max_recent = max(20, int(max_recent))
        self._lock = threading.RLock()
        self._handlers: dict[str, ChannelHandler] = {
            "macos": self._deliver_macos,
            "linux": self._deliver_linux,
            "windows": self._deliver_windows,
            "ntfy": self._deliver_ntfy,
            "webhook": self._deliver_federated_webhook,
            "federated_push": self._deliver_federated_webhook,
        }
        if channel_handlers:
            self._handlers.update(channel_handlers)
        self._init_db()

    def _secret(self) -> str:
        if self._hmac_secret:
            return self._hmac_secret
        return get_ecosystem_secret()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS notification_dedupe (
                    dedupe_key TEXT PRIMARY KEY,
                    notification_id TEXT NOT NULL,
                    expires_at REAL NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS notification_subscriptions (
                    subscriber_id TEXT PRIMARY KEY,
                    config_json TEXT NOT NULL,
                    updated_at REAL NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS notification_recent (
                    id TEXT PRIMARY KEY,
                    envelope_json TEXT NOT NULL,
                    privacy TEXT NOT NULL,
                    created_ts REAL NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS notification_deferred (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subscriber_id TEXT NOT NULL,
                    envelope_json TEXT NOT NULL,
                    created_ts REAL NOT NULL
                );
                """
            )
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass

    def upsert_subscription(self, sub: dict[str, Any]) -> dict[str, Any]:
        """Register or update a user/device notification subscription or federated push sink."""
        subscriber_id = str(sub.get("subscriber_id") or sub.get("device") or "").strip()
        if not subscriber_id:
            raise ValueError("subscriber_id (or device) is required")

        channels = sub.get("channels")
        if not isinstance(channels, list) or not channels:
            raise ValueError("channels must be a non-empty list")

        min_sev = str(sub.get("min_severity") or "medium").lower()
        if min_sev not in SEVERITY_RANK:
            raise ValueError(f"Invalid min_severity: {min_sev!r}")

        record = {
            "subscriber_id": subscriber_id,
            "device": str(sub.get("device") or subscriber_id),
            "channels": [str(c) for c in channels],
            "min_severity": min_sev,
            "quiet_hours": sub.get("quiet_hours"),
            "bypass_quiet_for": [
                str(s).lower() for s in (sub.get("bypass_quiet_for") or ["critical"])
            ],
            "webhook_url": sub.get("webhook_url"),
            "ntfy_url": sub.get("ntfy_url"),
            "ntfy_topic": sub.get("ntfy_topic"),
            "ntfy_token": sub.get("ntfy_token"),
            "enabled": bool(sub.get("enabled", True)),
        }
        now = time.time()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO notification_subscriptions
                (subscriber_id, config_json, updated_at)
                VALUES (?, ?, ?)
                """,
                (subscriber_id, json.dumps(record), now),
            )
        return self._public_subscription(record)

    @staticmethod
    def _public_subscription(record: dict[str, Any]) -> dict[str, Any]:
        out = dict(record)
        if out.get("ntfy_token"):
            out["ntfy_token"] = "***"
        return out

    def list_subscriptions(self, *, include_secrets: bool = False) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT config_json FROM notification_subscriptions ORDER BY subscriber_id ASC"
            ).fetchall()
        subs = [json.loads(r["config_json"]) for r in rows]
        if include_secrets:
            return subs
        return [self._public_subscription(s) for s in subs]

    def delete_subscription(self, subscriber_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM notification_subscriptions WHERE subscriber_id = ?",
                (subscriber_id,),
            )
            return cur.rowcount > 0

    def recent_notifications(
        self,
        *,
        limit: int = 50,
        include_local_only: bool = False,
        min_severity: str | None = None,
    ) -> list[dict[str, Any]]:
        floor = SEVERITY_RANK.get((min_severity or "low").lower(), 0)
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT envelope_json, privacy FROM notification_recent
                ORDER BY created_ts DESC
                LIMIT ?
                """,
                (max(1, min(int(limit), self._max_recent)),),
            ).fetchall()
        results: list[dict[str, Any]] = []
        for r in rows:
            if not include_local_only and r["privacy"] == "local_only":
                continue
            env = json.loads(r["envelope_json"])
            if SEVERITY_RANK.get(env.get("severity", "low"), 0) >= floor:
                results.append(env)
        return results

    def _check_and_record_dedupe(self, envelope: dict[str, Any], now_ts: float) -> str | None:
        """Return existing notification_id if deduplicated, else record and return None."""
        dedupe_key = envelope["dedupe_key"]
        ttl_sec = parse_ttl_seconds(envelope.get("ttl", "24h"))
        expires_at = now_ts + ttl_sec

        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM notification_dedupe WHERE expires_at <= ?", (now_ts,))
            row = conn.execute(
                "SELECT notification_id FROM notification_dedupe WHERE dedupe_key = ? AND expires_at > ?",
                (dedupe_key, now_ts),
            ).fetchone()
            if row is not None:
                return str(row["notification_id"])

            conn.execute(
                """
                INSERT OR REPLACE INTO notification_dedupe (dedupe_key, notification_id, expires_at)
                VALUES (?, ?, ?)
                """,
                (dedupe_key, envelope["id"], expires_at),
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO notification_recent (id, envelope_json, privacy, created_ts)
                VALUES (?, ?, ?, ?)
                """,
                (
                    envelope["id"],
                    json.dumps(envelope, separators=(",", ":"), sort_keys=True),
                    envelope.get("privacy", "redacted"),
                    now_ts,
                ),
            )
            conn.execute(
                """
                DELETE FROM notification_recent
                WHERE id NOT IN (
                    SELECT id FROM notification_recent ORDER BY created_ts DESC LIMIT ?
                )
                """,
                (self._max_recent,),
            )
            return None

    async def route(self, raw_envelope: dict[str, Any]) -> dict[str, Any]:
        """Validate, redact, deduplicate, apply quiet hours, and deliver across subscribed sinks."""
        assert_valid_schema(raw_envelope, "notification-envelope.v1")
        envelope = dict(raw_envelope)
        if envelope.get("privacy", "redacted") == "redacted":
            envelope["title"] = redact_notification_text(envelope["title"])
            envelope["body"] = redact_notification_text(envelope.get("body", ""))

        now_ts = time.time()
        existing_id = self._check_and_record_dedupe(envelope, now_ts)
        if existing_id is not None:
            return {
                "status": "deduplicated",
                "id": envelope["id"],
                "original_id": existing_id,
                "dedupe_key": envelope["dedupe_key"],
                "delivered": [],
                "deferred": [],
                "failed": [],
            }

        subs = [s for s in self.list_subscriptions(include_secrets=True) if s.get("enabled", True)]
        sev = envelope["severity"]
        sev_rank = SEVERITY_RANK.get(sev, 10)
        is_local_only = envelope.get("privacy") == "local_only"
        now_dt = self._clock()

        delivered: list[str] = []
        deferred: list[str] = []
        failed: list[str] = []

        for sub in subs:
            sub_id = sub["subscriber_id"]
            if sev_rank < SEVERITY_RANK.get(sub.get("min_severity", "medium"), 20):
                continue

            in_quiet = is_in_quiet_hours(sub.get("quiet_hours"), now_dt)
            bypass = sev in (sub.get("bypass_quiet_for") or ["critical"])
            if in_quiet and not bypass:
                self._store_deferred(sub_id, envelope, now_ts)
                deferred.append(sub_id)
                continue

            for ch in sub.get("channels", []):
                # Privacy guard: local_only notifications never leave the host over remote webhooks/ntfy.
                if is_local_only and ch in ("ntfy", "webhook", "federated_push"):
                    continue
                handler = self._handlers.get(ch)
                if handler is None:
                    failed.append(f"{sub_id}:{ch}")
                    continue
                try:
                    ok = await handler(envelope, sub)
                except Exception as exc:
                    logger.warning("Notification channel %s:%s error: %r", sub_id, ch, exc)
                    ok = False
                if ok:
                    delivered.append(f"{sub_id}:{ch}")
                else:
                    failed.append(f"{sub_id}:{ch}")

        return {
            "status": "routed",
            "id": envelope["id"],
            "dedupe_key": envelope["dedupe_key"],
            "delivered": delivered,
            "deferred": deferred,
            "failed": failed,
        }

    def _store_deferred(self, subscriber_id: str, envelope: dict[str, Any], now_ts: float) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO notification_deferred (subscriber_id, envelope_json, created_ts)
                VALUES (?, ?, ?)
                """,
                (subscriber_id, json.dumps(envelope), now_ts),
            )

    def deferred_count(self, subscriber_id: str | None = None) -> int:
        with self._lock, self._connect() as conn:
            if subscriber_id:
                row = conn.execute(
                    "SELECT COUNT(*) AS c FROM notification_deferred WHERE subscriber_id = ?",
                    (subscriber_id,),
                ).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) AS c FROM notification_deferred").fetchone()
            return int(row["c"]) if row else 0

    # ---- Built-in OS & Federated Mobile Push Channel Handlers ------------

    async def _deliver_macos(self, envelope: dict[str, Any], _sub: dict[str, Any]) -> bool:
        if sys.platform != "darwin" or not shutil.which("osascript"):
            return False
        # Pass strings via argv (`on run argv`) so arbitrary alert text can NEVER inject AppleScript.
        script = "on run argv\ndisplay notification (item 2 of argv) with title (item 1 of argv)\nend run"
        proc = await asyncio.create_subprocess_exec(
            "osascript",
            "-e",
            script,
            envelope["title"],
            envelope.get("body", ""),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=5.0)
        return proc.returncode == 0

    async def _deliver_linux(self, envelope: dict[str, Any], _sub: dict[str, Any]) -> bool:
        if not shutil.which("notify-send"):
            return False
        urgency_map = {
            "low": "low",
            "medium": "normal",
            "high": "normal",
            "critical": "critical",
        }
        urgency = urgency_map.get(envelope.get("severity", "medium"), "normal")
        proc = await asyncio.create_subprocess_exec(
            "notify-send",
            f"--urgency={urgency}",
            "--app-name=appEcosystem",
            envelope["title"],
            envelope.get("body", ""),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=5.0)
        return proc.returncode == 0

    async def _deliver_windows(self, envelope: dict[str, Any], _sub: dict[str, Any]) -> bool:
        ps = shutil.which("powershell.exe") or shutil.which("pwsh")
        if sys.platform != "win32" or not ps:
            return False
        # Pass strings via child environment variables so special characters cannot inject PowerShell.
        ps_cmd = (
            "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; "
            "$t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
            "$nodes = $t.GetElementsByTagName('text'); "
            "$nodes.Item(0).AppendChild($t.CreateTextNode($env:ECOSYSTEM_TOAST_TITLE)) > $null; "
            "$nodes.Item(1).AppendChild($t.CreateTextNode($env:ECOSYSTEM_TOAST_BODY)) > $null; "
            "$toast = [Windows.UI.Notifications.ToastNotification]::new($t); "
            "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('appEcosystem').Show($toast);"
        )
        env = os.environ.copy()
        env["ECOSYSTEM_TOAST_TITLE"] = envelope["title"]
        env["ECOSYSTEM_TOAST_BODY"] = envelope.get("body", "")
        proc = await asyncio.create_subprocess_exec(
            ps,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            ps_cmd,
            env=env,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=8.0)
        return proc.returncode == 0

    async def _deliver_ntfy(self, envelope: dict[str, Any], sub: dict[str, Any]) -> bool:
        base_url = (sub.get("ntfy_url") or os.environ.get("ECOSYSTEM_NTFY_URL") or "").strip().rstrip("/")
        topic = (sub.get("ntfy_topic") or os.environ.get("ECOSYSTEM_NTFY_TOPIC") or "appecosystem").strip().lstrip("/")
        if not base_url:
            return False

        prio_map = {"low": "2", "medium": "3", "high": "4", "critical": "5"}
        headers: dict[str, str] = {
            "Title": envelope["title"],
            "Priority": prio_map.get(envelope.get("severity", "medium"), "3"),
            "Tags": envelope["type"].replace(".", ","),
        }
        token = sub.get("ntfy_token") or os.environ.get("ECOSYSTEM_NTFY_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if envelope.get("deep_link"):
            headers["Click"] = str(envelope["deep_link"])

        url = f"{base_url}/{topic}"
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.post(
                url,
                content=(envelope.get("body") or envelope["title"]).encode("utf-8"),
                headers=headers,
            )
            return resp.status_code < 400

    async def _deliver_federated_webhook(self, envelope: dict[str, Any], sub: dict[str, Any]) -> bool:
        """Deliver signed notification to a sibling project's mobile push sink (OpenEye FCM, AegisSIEM iMessage, MagicMirrorRemote)."""
        webhook_url = (sub.get("webhook_url") or "").strip()
        if not webhook_url:
            return False
        headers = sign_request("POST", webhook_url, self._secret(), body=envelope)
        headers["Content-Type"] = "application/json"
        headers["X-Ecosystem-Event"] = envelope["type"]
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.post(webhook_url, json=envelope, headers=headers)
            return resp.status_code < 400

