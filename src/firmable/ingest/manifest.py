"""SQLite manifest: files, deliveries, chunks, snapshots, runs.

Only the coordinator process opens this database; workers never do.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

DDL = """
CREATE TABLE IF NOT EXISTS files (
    file_id       TEXT PRIMARY KEY,          -- SHA-256 of the full file content
    path          TEXT NOT NULL,             -- read-only source location
    size_bytes    INTEGER NOT NULL,
    snapshot_id   TEXT NOT NULL,
    chunk_bytes   INTEGER NOT NULL,
    status        TEXT NOT NULL,             -- registered | processing | completed | failed
    registered_at TEXT NOT NULL,
    completed_at  TEXT
);
CREATE TABLE IF NOT EXISTS deliveries (
    delivery_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    path          TEXT NOT NULL,
    file_id       TEXT NOT NULL REFERENCES files(file_id),
    snapshot_id   TEXT NOT NULL,
    outcome       TEXT NOT NULL,             -- new | duplicate
    registered_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chunks (
    file_id            TEXT NOT NULL REFERENCES files(file_id),
    chunk_index        INTEGER NOT NULL,
    start_byte         INTEGER NOT NULL,
    end_byte           INTEGER NOT NULL,
    status             TEXT NOT NULL,        -- pending | running | done | failed
    attempts           INTEGER NOT NULL DEFAULT 0,
    run_id             TEXT,
    last_error         TEXT,
    normalizer_version INTEGER,
    output_path        TEXT,
    quarantine_path    TEXT,
    input_digest       TEXT,                 -- SHA-256 over (offset, length, record_sha256) of owned lines
    lines              INTEGER,
    rows               INTEGER,
    blank              INTEGER,
    quarantined        INTEGER,
    quarantined_by_class TEXT,               -- JSON
    warnings           INTEGER,
    warnings_by_field  TEXT,                 -- JSON
    unknown_keys       TEXT,                 -- JSON
    unicode_repaired   INTEGER,
    bytes_read         INTEGER,
    wall_seconds       REAL,
    peak_rss_bytes     INTEGER,
    PRIMARY KEY (file_id, chunk_index)
);
CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id TEXT PRIMARY KEY,
    status      TEXT NOT NULL,               -- open | sealed
    sealed_at   TEXT
);
CREATE TABLE IF NOT EXISTS runs (
    run_id      TEXT PRIMARY KEY,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    workers     INTEGER NOT NULL,
    status      TEXT NOT NULL                -- running | finished | interrupted
);
"""


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, isolation_level=None)  # autocommit; explicit BEGIN where needed
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(DDL)
    return conn
