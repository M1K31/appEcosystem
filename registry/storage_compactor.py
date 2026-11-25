"""ECO-03: Offline Event Compaction & Edge WAL Archival.

Keeps long-running edge nodes and hubs within tight flash storage budgets by:
  1. Running safe SQLite ``PRAGMA wal_checkpoint(TRUNCATE)`` (and optional
     freelist-triggered ``VACUUM``) across ecosystem SQLite databases.
  2. Archiving aged/oversized ``.jsonl`` event logs into ``zstd`` (``*.zst``)
     archives when ``zstandard`` is installed, with automatic stdlib ``gzip``
     (``*.gz``) fallback, streaming in bounded 64 KiB chunks.
  3. Enforcing a strict archive retention budget (``max_archive_bytes`` and
     ``max_archive_files``), pruning oldest archives first.
"""
from __future__ import annotations

import asyncio
import gzip
import hashlib
import logging
import os
import secrets
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_CHUNK_SIZE = 65536

try:
    import zstandard as _zstd  # type: ignore[import-not-found]
except ImportError:
    _zstd = None


def has_zstd() -> bool:
    """Return True when the optional ``zstandard`` package is available."""
    return _zstd is not None


def _resolve_codec(codec: str) -> str:
    c = str(codec or "auto").strip().lower()
    if c == "auto":
        return "zstd" if _zstd is not None else "gzip"
    if c == "zstd":
        if _zstd is None:
            raise RuntimeError("zstd codec requested but 'zstandard' package is not installed")
        return "zstd"
    if c == "gzip":
        return "gzip"
    raise ValueError(f"Unsupported compression codec: {codec!r} (expected 'auto', 'zstd', or 'gzip')")


def compress_file_atomic(
    source_path: Path,
    dest_dir: Path,
    *,
    codec: str = "auto",
    timestamp: int | None = None,
) -> dict[str, Any]:
    """Stream-compress ``source_path`` into ``dest_dir`` atomically with 0o600 permissions."""
    resolved_codec = _resolve_codec(codec)
    ext = ".zst" if resolved_codec == "zstd" else ".gz"
    ts = int(time.time() if timestamp is None else timestamp)
    dest_dir.mkdir(parents=True, exist_ok=True)
    archive_name = f"{source_path.name}.{ts}.{secrets.token_hex(4)}{ext}"
    final_path = dest_dir / archive_name
    tmp_path = dest_dir / f".{archive_name}.tmp"

    raw_bytes = 0
    raw_hash = hashlib.sha256()

    fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as out_fh, source_path.open("rb") as in_fh:
            if resolved_codec == "zstd":
                cctx = _zstd.ZstdCompressor(level=3)
                with cctx.stream_writer(out_fh, closefd=False) as writer:
                    while True:
                        chunk = in_fh.read(_CHUNK_SIZE)
                        if not chunk:
                            break
                        raw_bytes += len(chunk)
                        raw_hash.update(chunk)
                        writer.write(chunk)
            else:
                with gzip.GzipFile(filename="", mode="wb", fileobj=out_fh, compresslevel=6, mtime=0) as gz:
                    while True:
                        chunk = in_fh.read(_CHUNK_SIZE)
                        if not chunk:
                            break
                        raw_bytes += len(chunk)
                        raw_hash.update(chunk)
                        gz.write(chunk)
        os.replace(tmp_path, final_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    compressed_bytes = final_path.stat().st_size
    return {
        "source": str(source_path),
        "archive_path": str(final_path),
        "codec": resolved_codec,
        "raw_bytes": raw_bytes,
        "compressed_bytes": compressed_bytes,
        "sha256_raw": raw_hash.hexdigest(),
    }


def decompress_archive(archive_path: str | Path) -> bytes:
    """Decompress a ``.zst`` or ``.gz`` event archive back to raw bytes."""
    p = Path(archive_path)
    if p.suffix == ".zst":
        if _zstd is None:
            raise RuntimeError("Cannot decompress .zst archive: 'zstandard' package is not installed")
        dctx = _zstd.ZstdDecompressor()
        with p.open("rb") as fh:
            return dctx.stream_reader(fh).read()
    if p.suffix == ".gz":
        with gzip.open(p, "rb") as fh:
            return fh.read()
    raise ValueError(f"Unsupported archive extension: {p.suffix!r}")


@dataclass
class WalCompactionResult:
    db_path: str
    wal_bytes_before: int
    wal_bytes_after: int
    db_bytes_before: int
    db_bytes_after: int
    checkpoint_busy: int
    checkpoint_log: int
    checkpoint_checkpointed: int
    vacuumed: bool = False
    error: str | None = None

    @property
    def bytes_reclaimed(self) -> int:
        return max(
            0,
            (self.wal_bytes_before + self.db_bytes_before)
            - (self.wal_bytes_after + self.db_bytes_after),
        )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["bytes_reclaimed"] = self.bytes_reclaimed
        return d


def compact_sqlite_db(
    db_path: str | Path,
    *,
    vacuum: bool = False,
    freelist_ratio_threshold: float = 0.25,
    busy_timeout_ms: int = 5000,
) -> WalCompactionResult:
    """Run ``PRAGMA wal_checkpoint(TRUNCATE)`` and optional ``VACUUM`` on a SQLite DB."""
    p = Path(db_path)
    wal_p = Path(f"{p}-wal")
    db_before = p.stat().st_size if p.is_file() else 0
    wal_before = wal_p.stat().st_size if wal_p.is_file() else 0

    if not p.is_file():
        return WalCompactionResult(
            db_path=str(p),
            wal_bytes_before=0,
            wal_bytes_after=0,
            db_bytes_before=0,
            db_bytes_after=0,
            checkpoint_busy=0,
            checkpoint_log=0,
            checkpoint_checkpointed=0,
            error="database file not found",
        )

    conn = sqlite3.connect(str(p), timeout=busy_timeout_ms / 1000.0)
    try:
        conn.execute(f"PRAGMA busy_timeout = {int(busy_timeout_ms)}")
        row = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        busy, log_frames, checkpointed = (int(row[0]), int(row[1]), int(row[2])) if row else (0, 0, 0)

        did_vacuum = False
        should_vacuum = vacuum
        if not should_vacuum and freelist_ratio_threshold > 0:
            page_count = int(conn.execute("PRAGMA page_count").fetchone()[0] or 0)
            freelist_count = int(conn.execute("PRAGMA freelist_count").fetchone()[0] or 0)
            if page_count > 0 and (freelist_count / page_count) >= freelist_ratio_threshold:
                should_vacuum = True

        if should_vacuum and busy == 0:
            conn.execute("VACUUM")
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            did_vacuum = True
    finally:
        conn.close()

    db_after = p.stat().st_size if p.is_file() else 0
    wal_after = wal_p.stat().st_size if wal_p.is_file() else 0
    return WalCompactionResult(
        db_path=str(p),
        wal_bytes_before=wal_before,
        wal_bytes_after=wal_after,
        db_bytes_before=db_before,
        db_bytes_after=db_after,
        checkpoint_busy=busy,
        checkpoint_log=log_frames,
        checkpoint_checkpointed=checkpointed,
        vacuumed=did_vacuum,
    )


def enforce_archive_retention(
    archive_dir: str | Path,
    *,
    max_archive_bytes: int = 50 * 1024 * 1024,
    max_archive_files: int = 100,
) -> list[str]:
    """Prune oldest ``.zst`` / ``.gz`` archives until within byte and count budgets."""
    d = Path(archive_dir)
    if not d.is_dir():
        return []
    archives = [
        p for p in d.iterdir()
        if p.is_file() and p.suffix in (".zst", ".gz")
    ]
    # Oldest first by mtime, then filename for determinism
    archives.sort(key=lambda p: (p.stat().st_mtime, p.name))

    total_bytes = sum(p.stat().st_size for p in archives)
    pruned: list[str] = []
    while archives and (len(archives) > max(1, int(max_archive_files)) or total_bytes > max(0, int(max_archive_bytes))):
        victim = archives.pop(0)
        size = victim.stat().st_size
        try:
            victim.unlink()
            total_bytes -= size
            pruned.append(str(victim))
        except OSError:
            break
    return pruned


@dataclass
class CompactionReport:
    data_dir: str
    sqlite_results: list[dict[str, Any]] = field(default_factory=list)
    archived_logs: list[dict[str, Any]] = field(default_factory=list)
    pruned_archives: list[str] = field(default_factory=list)
    total_bytes_reclaimed: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EdgeStorageCompactor:
    """Orchestrates SQLite WAL compaction and event log archival for a data directory."""

    def __init__(
        self,
        data_dir: str | Path,
        *,
        archive_dir: str | Path | None = None,
        codec: str = "auto",
        min_archive_bytes: int = 1024 * 1024,
        max_log_age_seconds: int = 86400,
        max_archive_bytes: int = 50 * 1024 * 1024,
        max_archive_files: int = 100,
    ):
        self.data_dir = Path(data_dir)
        self.archive_dir = Path(archive_dir) if archive_dir else (self.data_dir / "archives")
        self.codec = codec
        self.min_archive_bytes = max(0, int(min_archive_bytes))
        self.max_log_age_seconds = max(0, int(max_log_age_seconds))
        self.max_archive_bytes = max(0, int(max_archive_bytes))
        self.max_archive_files = max(1, int(max_archive_files))

    def compact_all_databases(self, *, vacuum: bool = False) -> list[WalCompactionResult]:
        if not self.data_dir.is_dir():
            return []
        results: list[WalCompactionResult] = []
        for db_file in sorted(self.data_dir.glob("*.db")):
            if db_file.is_file():
                results.append(compact_sqlite_db(db_file, vacuum=vacuum))
        return results

    def archive_event_logs(self, *, now: float | None = None) -> list[dict[str, Any]]:
        if not self.data_dir.is_dir():
            return []
        ts = time.time() if now is None else now
        archived: list[dict[str, Any]] = []
        for log_file in sorted(self.data_dir.glob("*.jsonl")):
            if not log_file.is_file():
                continue
            stat = log_file.stat()
            if stat.st_size == 0:
                continue
            age = ts - stat.st_mtime
            if stat.st_size < self.min_archive_bytes and age < self.max_log_age_seconds:
                continue
            record = compress_file_atomic(log_file, self.archive_dir, codec=self.codec, timestamp=int(ts))
            # Truncate source only after durable atomic archive replacement
            log_file.write_bytes(b"")
            archived.append(record)
        return archived

    def run_once(self, *, vacuum: bool = False, now: float | None = None) -> CompactionReport:
        db_results = self.compact_all_databases(vacuum=vacuum)
        archived = self.archive_event_logs(now=now)
        pruned = enforce_archive_retention(
            self.archive_dir,
            max_archive_bytes=self.max_archive_bytes,
            max_archive_files=self.max_archive_files,
        )
        reclaimed = sum(r.bytes_reclaimed for r in db_results) + sum(
            max(0, a["raw_bytes"] - a["compressed_bytes"]) for a in archived
        )
        return CompactionReport(
            data_dir=str(self.data_dir),
            sqlite_results=[r.to_dict() for r in db_results],
            archived_logs=archived,
            pruned_archives=pruned,
            total_bytes_reclaimed=reclaimed,
        )


class StorageCompactionScheduler:
    """Periodic asyncio background task running ``EdgeStorageCompactor.run_once``."""

    def __init__(
        self,
        compactor: EdgeStorageCompactor,
        *,
        interval_seconds: int = 3600,
    ):
        self.compactor = compactor
        self.interval_seconds = max(0, int(interval_seconds))
        self._task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()

    async def start(self) -> None:
        if self.interval_seconds <= 0 or self._task is not None:
            return
        self._stop_event.clear()
        self._task = asyncio.create_task(self._loop(), name="edge-storage-compactor")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop_event.set()
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None

    async def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=float(self.interval_seconds))
                break
            except asyncio.TimeoutError:
                pass
            try:
                report = await asyncio.to_thread(self.compactor.run_once)
                if report.total_bytes_reclaimed > 0 or report.archived_logs or report.pruned_archives:
                    logger.info(
                        "Edge storage compaction complete: reclaimed=%dB archived=%d pruned=%d",
                        report.total_bytes_reclaimed,
                        len(report.archived_logs),
                        len(report.pruned_archives),
                    )
            except Exception as exc:
                logger.warning("Periodic edge storage compaction failed: %s", exc)
