"""ECO-03 tests: Offline Event Compaction & Edge WAL Archival."""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from cli.commands import cmd_compact
from registry.storage_compactor import (
    EdgeStorageCompactor,
    compact_sqlite_db,
    decompress_archive,
    enforce_archive_retention,
)


def test_sqlite_wal_checkpoint_truncates_wal_and_reclaims_freelist(tmp_path: Path):
    db_path = tmp_path / "edge_events.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, payload TEXT)")
    blob = "x" * 4096
    conn.executemany("INSERT INTO events (payload) VALUES (?)", [(blob,) for _ in range(120)])
    conn.commit()
    # Delete most rows to create freelist pages
    conn.execute("DELETE FROM events WHERE id > 10")
    conn.commit()
    # Keep connection open (simulating a live daemon) so the WAL file remains active on disk
    wal_path = Path(f"{db_path}-wal")
    assert wal_path.is_file() and wal_path.stat().st_size > 0

    try:
        res = compact_sqlite_db(db_path, vacuum=True)
    finally:
        conn.close()
    assert res.error is None
    assert res.wal_bytes_before > 0
    assert res.wal_bytes_after == 0
    assert res.vacuumed is True
    assert res.bytes_reclaimed > 0

    # Data integrity preserved
    verify = sqlite3.connect(str(db_path))
    assert verify.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 10
    verify.close()


def test_offline_event_log_archival_compression_and_retention_budget(tmp_path: Path):
    log_file = tmp_path / "offline_events.jsonl"
    sample_lines = "".join(
        json.dumps({"seq": i, "event": "security.motion", "zone": "driveway", "pad": "A" * 128}) + "\n"
        for i in range(100)
    )
    log_file.write_text(sample_lines, encoding="utf-8")

    compactor = EdgeStorageCompactor(
        data_dir=tmp_path,
        min_archive_bytes=1024,
        max_archive_bytes=10_000,
        max_archive_files=2,
    )
    report1 = compactor.run_once(now=2000.0)
    assert len(report1.archived_logs) == 1
    arc = report1.archived_logs[0]
    assert arc["compressed_bytes"] < arc["raw_bytes"]
    assert log_file.stat().st_size == 0  # truncated after durable archive

    # Round-trip decompression matches original bytes exactly
    restored = decompress_archive(arc["archive_path"]).decode("utf-8")
    assert restored == sample_lines

    # Write 2 more logs so total archives exceed max_archive_files=2 -> oldest pruned
    for step in (1, 2):
        log_file.write_text(sample_lines, encoding="utf-8")
        rep = compactor.run_once(now=2000.0 + step * 10)
        if step == 2:
            assert len(rep.pruned_archives) >= 1

    remaining = list((tmp_path / "archives").glob("*.jsonl.*"))
    assert len(remaining) <= 2


def test_enforce_archive_retention_prunes_by_byte_budget(tmp_path: Path):
    arc_dir = tmp_path / "archives"
    arc_dir.mkdir()
    for i in range(4):
        f = arc_dir / f"events.{i}.gz"
        f.write_bytes(b"0" * 1000)
        os.utime(f, (1000 + i, 1000 + i))

    pruned = enforce_archive_retention(arc_dir, max_archive_bytes=2000, max_archive_files=10)
    assert len(pruned) == 2
    remaining = sorted(p.name for p in arc_dir.iterdir())
    assert remaining == ["events.2.gz", "events.3.gz"]


def test_cmd_compact_cli_runs_cleanly(tmp_path: Path, capsys):
    db_path = tmp_path / "approvals.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
    conn.execute("INSERT INTO t VALUES (1)")
    conn.commit()
    conn.close()

    rc = cmd_compact(str(tmp_path), vacuum=True)
    assert rc == 0
    out = capsys.readouterr().out
    assert "SQLite DBs checked:  1" in out
