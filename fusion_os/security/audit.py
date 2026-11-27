"""Hash-chained, append-only audit log.

Every entry stores the SHA-256 of the previous entry, so editing or removing a row breaks the chain and
`verify()` reports the first broken sequence number. SQLite triggers also refuse UPDATE/DELETE.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Optional

from .store import Store

GENESIS = "0" * 64
_SECRET_KEYS = ("token", "password", "secret", "api_key", "apikey", "authorization", "cookie", "private_key")


def redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("[REDACTED]" if any(s in k.lower() for s in _SECRET_KEYS) else redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _entry_hash(prev: str, ts: float, actor: str, event: str, data: str) -> str:
    return hashlib.sha256(_canon([prev, repr(ts), actor, event, data]).encode()).hexdigest()


class AuditLog:
    def __init__(self, store: Store):
        self.store = store

    def append(self, actor: str, event: str, data: Optional[dict] = None) -> dict:
        payload = _canon(redact(data or {}))
        with self.store.lock:
            row = self.store.query("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1")
            prev = row[0]["hash"] if row else GENESIS
            ts = time.time()
            h = _entry_hash(prev, ts, actor, event, payload)
            cur = self.store.execute(
                "INSERT INTO audit(ts, actor, event, data, prev_hash, hash) VALUES (?,?,?,?,?,?)",
                (ts, actor, event, payload, prev, h),
            )
        return {"seq": cur.lastrowid, "ts": ts, "actor": actor, "event": event, "hash": h}

    def entries(self, limit: int = 200, after_seq: int = 0, event_prefix: str = "") -> list[dict]:
        rows = self.store.query(
            "SELECT * FROM audit WHERE seq > ? AND event LIKE ? ORDER BY seq DESC LIMIT ?",
            (after_seq, event_prefix + "%", max(1, min(limit, 5000))),
        )
        return [
            {"seq": r["seq"], "ts": r["ts"], "actor": r["actor"], "event": r["event"],
             "data": json.loads(r["data"]), "hash": r["hash"]}
            for r in rows
        ]

    def verify(self) -> dict:
        prev = GENESIS
        count = 0
        for r in self.store.query("SELECT * FROM audit ORDER BY seq ASC"):
            if r["prev_hash"] != prev or _entry_hash(prev, r["ts"], r["actor"], r["event"], r["data"]) != r["hash"]:
                return {"ok": False, "entries": count, "broken_at": r["seq"]}
            prev = r["hash"]
            count += 1
        return {"ok": True, "entries": count, "head": prev}
