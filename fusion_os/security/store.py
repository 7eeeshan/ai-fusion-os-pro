"""SQLite store for the security controller (one file, owned by the controller only)."""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  actor TEXT NOT NULL,
  event TEXT NOT NULL,
  data TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;

CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  created REAL NOT NULL,
  expires REAL NOT NULL,
  agent_id TEXT NOT NULL,
  action TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  request TEXT NOT NULL,
  reason TEXT NOT NULL,
  status TEXT NOT NULL,          -- pending | approved | denied | used | expired
  decided_by TEXT,
  decided_at REAL,
  note TEXT
);

CREATE TABLE IF NOT EXISTS engagements (
  id TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  created REAL NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS engagement_usage (
  engagement_id TEXT PRIMARY KEY,
  requests INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS budgets (
  mission_id TEXT PRIMARY KEY,
  max_calls INTEGER NOT NULL,
  max_seconds REAL NOT NULL,
  max_usd REAL NOT NULL,
  used_calls INTEGER NOT NULL DEFAULT 0,
  used_seconds REAL NOT NULL DEFAULT 0,
  used_usd REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS agents (
  agent_id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  zones TEXT NOT NULL,
  created REAL NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);
"""


class Store:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self.lock:
            return self.conn.execute(sql, params)

    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self.lock:
            return list(self.conn.execute(sql, params))

    def close(self) -> None:
        with self.lock:
            self.conn.close()
