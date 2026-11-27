"""Versioned runtime configuration (prompts, routing, deployed models). Every change keeps the previous value so
it can be rolled back; changes are recorded in the audit log by the callers."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Optional


class ConfigStore:
    def __init__(self, path: Path):
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("CREATE TABLE IF NOT EXISTS config (key TEXT, version INTEGER, value TEXT, by TEXT, at REAL, "
                          "note TEXT, PRIMARY KEY(key, version))")

    def get(self, key: str, default: Any = None) -> Any:
        r = self.conn.execute("SELECT value FROM config WHERE key=? ORDER BY version DESC LIMIT 1", (key,)).fetchone()
        return json.loads(r["value"]) if r else default

    def set(self, key: str, value: Any, by: str, note: str = "") -> int:
        with self.lock:
            r = self.conn.execute("SELECT max(version) AS v FROM config WHERE key=?", (key,)).fetchone()
            v = (r["v"] or 0) + 1
            self.conn.execute("INSERT INTO config VALUES (?,?,?,?,?,?)", (key, v, json.dumps(value), by, time.time(), note))
        return v

    def rollback(self, key: str, by: str) -> Optional[Any]:
        """Re-apply the previous version as a new version (history is never rewritten)."""
        rows = self.conn.execute("SELECT value FROM config WHERE key=? ORDER BY version DESC LIMIT 2", (key,)).fetchall()
        if len(rows) < 2:
            return None
        prev = json.loads(rows[1]["value"])
        self.set(key, prev, by, "rollback")
        return prev

    def history(self, key: str) -> list[dict]:
        return [dict(r) | {"value": json.loads(r["value"])} for r in
                self.conn.execute("SELECT * FROM config WHERE key=? ORDER BY version DESC LIMIT 50", (key,))]

    def keys(self) -> list[str]:
        return [r["key"] for r in self.conn.execute("SELECT DISTINCT key FROM config ORDER BY key")]
