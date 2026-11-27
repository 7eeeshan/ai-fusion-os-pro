"""Human approval queue. Approvals are single-use and bound to the exact request fingerprint."""
from __future__ import annotations

import json
import secrets
import time
from typing import Optional

from .store import Store


class ApprovalQueue:
    def __init__(self, store: Store):
        self.store = store

    def request(self, agent_id: str, action: str, fingerprint: str, request: dict, reason: str, ttl: int) -> str:
        # Reuse an identical pending request instead of flooding the queue.
        rows = self.store.query(
            "SELECT id FROM approvals WHERE request_hash=? AND status='pending' AND expires>?", (fingerprint, time.time())
        )
        if rows:
            return rows[0]["id"]
        aid = "apr_" + secrets.token_hex(8)
        now = time.time()
        self.store.execute(
            "INSERT INTO approvals(id, created, expires, agent_id, action, request_hash, request, reason, status) "
            "VALUES (?,?,?,?,?,?,?,?, 'pending')",
            (aid, now, now + ttl, agent_id, action, fingerprint, json.dumps(request, default=str), reason),
        )
        return aid

    def _expire(self) -> None:
        self.store.execute("UPDATE approvals SET status='expired' WHERE status IN ('pending','approved') AND expires<?",
                           (time.time(),))

    def list(self, status: Optional[str] = None, limit: int = 200) -> list[dict]:
        self._expire()
        sql = "SELECT * FROM approvals"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY created DESC LIMIT ?"
        rows = self.store.query(sql, params + (limit,))
        return [{**dict(r), "request": json.loads(r["request"])} for r in rows]

    def decide(self, aid: str, approve: bool, by: str, note: str = "") -> bool:
        self._expire()
        cur = self.store.execute(
            "UPDATE approvals SET status=?, decided_by=?, decided_at=?, note=? WHERE id=? AND status='pending'",
            ("approved" if approve else "denied", by, time.time(), note, aid),
        )
        return cur.rowcount > 0

    def consume(self, aid: str, fingerprint: str) -> tuple[bool, str]:
        """Atomically mark an approved request as used. Fails if it doesn't match the request being made."""
        self._expire()
        rows = self.store.query("SELECT status, request_hash FROM approvals WHERE id=?", (aid,))
        if not rows:
            return False, "unknown approval"
        if rows[0]["request_hash"] != fingerprint:
            return False, "approval was granted for a different request"
        if rows[0]["status"] != "approved":
            return False, f"approval is {rows[0]['status']}"
        cur = self.store.execute("UPDATE approvals SET status='used' WHERE id=? AND status='approved'", (aid,))
        return (cur.rowcount > 0), ("ok" if cur.rowcount else "approval already used")
