"""Persistent job queue with leases, idempotency keys, capability routing and recurring schedules.

- Idempotency: a job's key is unique, so the same work enqueued twice (for example by two schedulers, or by the
  local machine and the cloud during a hand-over) exists once.
- Leases: a worker holds a job for a short lease and must heartbeat. If the worker disappears (PC switched off), the
  lease expires and another worker picks the job up. A job whose lease expired cannot be completed by the old worker,
  so work is never recorded twice.
- Routing: a job may require capabilities (e.g. `local-engine`, `docker`); only nodes that advertise them lease it.
  Jobs that prefer local inference can declare a fallback so a cloud node takes them when no local node is alive.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from ..db import SafeConn
from typing import Any, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, payload TEXT NOT NULL, idem TEXT UNIQUE, status TEXT NOT NULL,
  requires TEXT NOT NULL, fallback_requires TEXT, priority INTEGER NOT NULL DEFAULT 5, run_after REAL NOT NULL,
  lease_owner TEXT, lease_until REAL, attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 3,
  result TEXT, error TEXT, created REAL NOT NULL, updated REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS jobs_ready ON jobs(status, run_after, priority);
CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY, location TEXT, capabilities TEXT, last_seen REAL, info TEXT);
CREATE TABLE IF NOT EXISTS schedules (name TEXT PRIMARY KEY, kind TEXT, payload TEXT, interval_s REAL, requires TEXT,
  next_run REAL, enabled INTEGER NOT NULL DEFAULT 1);
"""
NODE_TIMEOUT = 90.0


class JobQueue:
    def __init__(self, path: Path, lease_s: float = 60.0):
        self.lease_s = lease_s
        self.lock = threading.RLock()
        self.conn = SafeConn(path)
        self.conn.executescript(SCHEMA)

    # ---------- producers ----------
    def enqueue(self, kind: str, payload: dict, *, idem: Optional[str] = None, requires: Optional[list[str]] = None,
                fallback_requires: Optional[list[str]] = None, priority: int = 5, delay_s: float = 0,
                max_attempts: int = 3) -> tuple[str, bool]:
        """Returns (job_id, created). With an existing idempotency key the existing job id is returned."""
        now = time.time()
        jid = "job_" + secrets.token_hex(8)
        with self.lock:
            try:
                self.conn.execute(
                    "INSERT INTO jobs(id, kind, payload, idem, status, requires, fallback_requires, priority, run_after, "
                    "max_attempts, created, updated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (jid, kind, json.dumps(payload), idem, "queued", json.dumps(sorted(requires or [])),
                     json.dumps(sorted(fallback_requires)) if fallback_requires is not None else None, priority,
                     now + delay_s, max_attempts, now, now))
                return jid, True
            except sqlite3.IntegrityError:
                r = self.conn.execute("SELECT id FROM jobs WHERE idem=?", (idem,)).fetchone()
                return r["id"], False

    # ---------- nodes ----------
    def register_node(self, node_id: str, location: str, capabilities: list[str], info: Optional[dict] = None) -> None:
        with self.lock:
            self.conn.execute("INSERT INTO nodes VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET location=excluded.location, "
                              "capabilities=excluded.capabilities, last_seen=excluded.last_seen, info=excluded.info",
                              (node_id, location, json.dumps(sorted(capabilities)), time.time(), json.dumps(info or {})))

    def nodes(self) -> list[dict]:
        now = time.time()
        return [dict(r) | {"capabilities": json.loads(r["capabilities"]), "info": json.loads(r["info"] or "{}"),
                           "alive": now - r["last_seen"] < NODE_TIMEOUT} for r in self.conn.execute("SELECT * FROM nodes")]

    def _alive_caps(self) -> set[str]:
        caps: set[str] = set()
        for n in self.nodes():
            if n["alive"]:
                caps |= set(n["capabilities"])
        return caps

    # ---------- consumers ----------
    def _requeue_expired(self) -> None:
        now = time.time()
        with self.lock:
            self.conn.execute("UPDATE jobs SET status='queued', lease_owner=NULL, lease_until=NULL, updated=? "
                              "WHERE status='leased' AND lease_until < ? AND attempts < max_attempts", (now, now))
            self.conn.execute("UPDATE jobs SET status='failed', error=COALESCE(error,'lease expired too many times'), updated=? "
                              "WHERE status='leased' AND lease_until < ? AND attempts >= max_attempts", (now, now))

    def lease(self, node_id: str, capabilities: list[str], location: str = "local") -> Optional[dict]:
        self.register_node(node_id, location, capabilities)
        self._requeue_expired()
        caps = set(capabilities)
        alive = self._alive_caps()
        now = time.time()
        with self.lock:
            for r in self.conn.execute("SELECT * FROM jobs WHERE status='queued' AND run_after<=? ORDER BY priority, created LIMIT 50", (now,)):
                req = set(json.loads(r["requires"]))
                ok = req <= caps
                if not ok and r["fallback_requires"] is not None:
                    # Fall back only when no live node can satisfy the preferred requirements.
                    ok = set(json.loads(r["fallback_requires"])) <= caps and not req <= alive
                if not ok:
                    continue
                cur = self.conn.execute("UPDATE jobs SET status='leased', lease_owner=?, lease_until=?, attempts=attempts+1, updated=? "
                                        "WHERE id=? AND status='queued'", (node_id, now + self.lease_s, now, r["id"]))
                if cur.rowcount:
                    return {"id": r["id"], "kind": r["kind"], "payload": json.loads(r["payload"]), "attempt": r["attempts"] + 1,
                            "lease_until": now + self.lease_s}
        return None

    def heartbeat(self, job_id: str, node_id: str) -> bool:
        now = time.time()
        with self.lock:
            return self.conn.execute("UPDATE jobs SET lease_until=?, updated=? WHERE id=? AND lease_owner=? AND status='leased' "
                                     "AND lease_until>=?", (now + self.lease_s, now, job_id, node_id, now)).rowcount > 0

    def complete(self, job_id: str, node_id: str, result: Any) -> bool:
        """Only the current lease holder, with an unexpired lease, may complete a job."""
        now = time.time()
        with self.lock:
            return self.conn.execute("UPDATE jobs SET status='done', result=?, lease_until=NULL, updated=? WHERE id=? AND "
                                     "lease_owner=? AND status='leased' AND lease_until>=?",
                                     (json.dumps(result, default=str)[:200000], now, job_id, node_id, now)).rowcount > 0

    def fail(self, job_id: str, node_id: str, error: str, retry_in_s: float = 30) -> bool:
        now = time.time()
        with self.lock:
            r = self.conn.execute("SELECT attempts, max_attempts FROM jobs WHERE id=? AND lease_owner=? AND status='leased'",
                                  (job_id, node_id)).fetchone()
            if not r:
                return False
            final = r["attempts"] >= r["max_attempts"]
            self.conn.execute("UPDATE jobs SET status=?, error=?, lease_owner=NULL, lease_until=NULL, run_after=?, updated=? WHERE id=?",
                              ("failed" if final else "queued", error[:4000], now + retry_in_s * r["attempts"], now, job_id))
            return True

    def get(self, job_id: str) -> Optional[dict]:
        r = self.conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return dict(r) | {"payload": json.loads(r["payload"])} if r else None

    def stats(self) -> dict:
        rows = self.conn.execute("SELECT status, count(*) AS n FROM jobs GROUP BY status").fetchall()
        oldest = self.conn.execute("SELECT min(created) AS t FROM jobs WHERE status='queued'").fetchone()["t"]
        return {"by_status": {r["status"]: r["n"] for r in rows}, "oldest_queued_age_s": (time.time() - oldest) if oldest else 0}

    def recent(self, limit: int = 50) -> list[dict]:
        return [dict(r) | {"payload": None, "result": None} for r in
                self.conn.execute("SELECT * FROM jobs ORDER BY updated DESC LIMIT ?", (limit,))]

    # ---------- schedules ----------
    def schedule(self, name: str, kind: str, payload: dict, interval_s: float, requires: Optional[list[str]] = None) -> None:
        with self.lock:
            self.conn.execute("INSERT INTO schedules VALUES (?,?,?,?,?,?,1) ON CONFLICT(name) DO UPDATE SET kind=excluded.kind, "
                              "payload=excluded.payload, interval_s=excluded.interval_s, requires=excluded.requires",
                              (name, kind, json.dumps(payload), interval_s, json.dumps(requires or []), time.time()))

    def schedules(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM schedules")]

    def tick(self) -> list[str]:
        """Enqueue due scheduled jobs. Idempotent per time slot, so several schedulers never double-enqueue."""
        now = time.time()
        out = []
        for s in self.conn.execute("SELECT * FROM schedules WHERE enabled=1 AND next_run<=?", (now,)).fetchall():
            slot = int(now // s["interval_s"])
            jid, created = self.enqueue(s["kind"], json.loads(s["payload"]), idem=f"sched:{s['name']}:{slot}",
                                        requires=json.loads(s["requires"]))
            with self.lock:
                self.conn.execute("UPDATE schedules SET next_run=? WHERE name=?", ((slot + 1) * s["interval_s"], s["name"]))
            if created:
                out.append(jid)
        return out
