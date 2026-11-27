"""Thread-safe SQLite access. The API serves requests from a thread pool and workers run in threads, so every
statement on a shared connection runs under one lock and its rows are fetched before the lock is released."""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterator


class Result:
    def __init__(self, rows: list[sqlite3.Row], rowcount: int, lastrowid: Any):
        self.rows, self.rowcount, self.lastrowid = rows, rowcount, lastrowid

    def fetchone(self) -> Any:
        return self.rows[0] if self.rows else None

    def fetchall(self) -> list[sqlite3.Row]:
        return self.rows

    def __iter__(self) -> Iterator[sqlite3.Row]:
        return iter(self.rows)


class SafeConn:
    def __init__(self, path: Path | str, wal: bool = True):
        self.lock = threading.RLock()
        self._c = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None, timeout=30)
        self._c.row_factory = sqlite3.Row
        if wal:
            self._c.execute("PRAGMA journal_mode=WAL")

    def execute(self, sql: str, params: Any = ()) -> Result:
        with self.lock:
            cur = self._c.execute(sql, params)
            rows = cur.fetchall() if cur.description else []
            return Result(rows, cur.rowcount, cur.lastrowid)

    def executescript(self, sql: str) -> None:
        with self.lock:
            self._c.executescript(sql)

    def close(self) -> None:
        with self.lock:
            self._c.close()
