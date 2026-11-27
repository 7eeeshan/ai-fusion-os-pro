"""Persistent memory: semantic facts, episodic mission history, procedural know-how, and a knowledge graph.

Retrieval is BM25 full-text search (SQLite FTS5), optionally blended with vector similarity when an embedding
function is supplied (e.g. from AI Fusion Engine Pro). Every record carries provenance.

Poisoning defences:
- trust levels: `verified` (admin or a passed verification), `user`, `agent`, `external`. Agents cannot write
  `verified`; only `promote()` (admin path) can.
- content from external sources is scanned for injection patterns; suspicious records are quarantined and never
  returned by search until an admin releases them.
- `external` records come back wrapped as untrusted content, so they are always presented to models as data.
- the same content hash from the same source is not stored twice; records can be retracted (kept for audit).
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
import sqlite3
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Literal, Optional

from ..db import SafeConn
from ..security.untrusted import UntrustedContent, scan

Kind = Literal["semantic", "episodic", "procedural"]
Trust = Literal["verified", "user", "agent", "external"]
KINDS = ("semantic", "episodic", "procedural")
TRUST_RANK = {"verified": 3, "user": 2, "agent": 1, "external": 0}
Embedder = Callable[[str], list[float]]

SCHEMA = """
CREATE TABLE IF NOT EXISTS memories (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, content TEXT NOT NULL, tags TEXT NOT NULL,
  source TEXT NOT NULL, source_type TEXT NOT NULL, trust TEXT NOT NULL,
  agent_id TEXT, mission_id TEXT, created REAL NOT NULL, sha256 TEXT NOT NULL,
  status TEXT NOT NULL, findings TEXT NOT NULL, uses INTEGER NOT NULL DEFAULT 0, embedding BLOB
);
CREATE UNIQUE INDEX IF NOT EXISTS mem_dedupe ON memories(sha256, source);
CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(content, tags, content='memories', content_rowid='rowid');
CREATE TRIGGER IF NOT EXISTS mem_ai AFTER INSERT ON memories BEGIN
  INSERT INTO memories_fts(rowid, content, tags) VALUES (new.rowid, new.content, new.tags); END;
CREATE TRIGGER IF NOT EXISTS mem_ad AFTER DELETE ON memories BEGIN
  INSERT INTO memories_fts(memories_fts, rowid, content, tags) VALUES('delete', old.rowid, old.content, old.tags); END;

CREATE TABLE IF NOT EXISTS graph (
  subject TEXT NOT NULL, predicate TEXT NOT NULL, object TEXT NOT NULL,
  memory_id TEXT, trust TEXT NOT NULL, created REAL NOT NULL,
  PRIMARY KEY (subject, predicate, object)
);
CREATE INDEX IF NOT EXISTS graph_obj ON graph(object);

CREATE TABLE IF NOT EXISTS episodes (
  id TEXT PRIMARY KEY, mission_id TEXT, goal TEXT NOT NULL, steps TEXT NOT NULL,
  outcome TEXT NOT NULL, error TEXT, resolution TEXT, agent_id TEXT, created REAL NOT NULL
);
CREATE VIRTUAL TABLE IF NOT EXISTS episodes_fts USING fts5(goal, error, resolution, content='episodes', content_rowid='rowid');
CREATE TRIGGER IF NOT EXISTS ep_ai AFTER INSERT ON episodes BEGIN
  INSERT INTO episodes_fts(rowid, goal, error, resolution) VALUES (new.rowid, new.goal, coalesce(new.error,''), coalesce(new.resolution,'')); END;
CREATE TRIGGER IF NOT EXISTS ep_au AFTER UPDATE ON episodes BEGIN
  INSERT INTO episodes_fts(episodes_fts, rowid, goal, error, resolution) VALUES('delete', old.rowid, old.goal, coalesce(old.error,''), coalesce(old.resolution,''));
  INSERT INTO episodes_fts(rowid, goal, error, resolution) VALUES (new.rowid, new.goal, coalesce(new.error,''), coalesce(new.resolution,'')); END;
"""


@dataclass
class MemoryRecord:
    id: str
    kind: str
    content: str
    tags: list[str]
    source: str
    source_type: str
    trust: str
    agent_id: Optional[str]
    mission_id: Optional[str]
    created: float
    status: str
    findings: list[dict] = field(default_factory=list)
    score: float = 0.0

    def for_prompt(self) -> str:
        """How a model sees this memory. External-trust content is always wrapped as untrusted data."""
        if self.trust == "external":
            uc = UntrustedContent(self.source, self.source_type, self.content, "", self.created)
            return uc.render()
        return f"[memory {self.id} · {self.kind} · trust={self.trust} · source={self.source}]\n{self.content}"

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


_STOP = set("""a an and are as at be been but by can could did do does for from had has have how i if in into is it
its me my no not of on or our should so than that the their them then there these they this to us was we were what
when where which who why will with would you your""".split())


def _fts_query(text: str) -> str:
    words = [w for w in re.findall(r"[\w]{2,}", text.lower()) if w not in _STOP][:24]
    return " OR ".join(f'"{w}"' for w in words)


def _pack(v: list[float]) -> bytes:
    return struct.pack(f"{len(v)}f", *v)


def _unpack(b: bytes) -> list[float]:
    return list(struct.unpack(f"{len(b) // 4}f", b))


def _cos(a: list[float], b: list[float]) -> float:
    if len(a) != len(b) or not a:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


class MemoryStore:
    def __init__(self, path: Path, embedder: Optional[Embedder] = None):
        self.lock = threading.RLock()
        self.conn = SafeConn(path)
        self.conn.executescript(SCHEMA)
        self.embedder = embedder

    def _q(self, sql: str, p: tuple = ()) -> list[sqlite3.Row]:
        with self.lock:
            return list(self.conn.execute(sql, p))

    def _x(self, sql: str, p: tuple = ()) -> sqlite3.Cursor:
        with self.lock:
            return self.conn.execute(sql, p)

    # ---------- semantic / procedural ----------
    def write(self, content: str, kind: Kind = "semantic", *, source: str, source_type: str = "agent",
              trust: Trust = "agent", agent_id: Optional[str] = None, mission_id: Optional[str] = None,
              tags: Optional[list[str]] = None) -> MemoryRecord:
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {KINDS}")
        if trust == "verified":
            raise PermissionError("agents cannot write verified memories; use promote() through the admin path")
        if trust not in TRUST_RANK:
            raise ValueError("bad trust level")
        content = content.strip()
        if not content or len(content) > 50_000:
            raise ValueError("memory content must be 1..50000 characters")
        findings = scan(content)
        status = "quarantined" if findings and trust in ("external", "agent") else "active"
        sha = hashlib.sha256(content.encode()).hexdigest()
        existing = self._q("SELECT id FROM memories WHERE sha256=? AND source=?", (sha, source))
        if existing:
            return self.get(existing[0]["id"])  # type: ignore[return-value]
        emb = _pack(self.embedder(content)) if (self.embedder and status == "active") else None
        mid = "mem_" + secrets.token_hex(8)
        self._x(
            "INSERT INTO memories(id, kind, content, tags, source, source_type, trust, agent_id, mission_id, created, "
            "sha256, status, findings, embedding) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (mid, kind, content, " ".join(tags or []), source, source_type, trust, agent_id, mission_id, time.time(),
             sha, status, json.dumps([f.__dict__ for f in findings]), emb),
        )
        return self.get(mid)  # type: ignore[return-value]

    def _rec(self, r: sqlite3.Row, score: float = 0.0) -> MemoryRecord:
        return MemoryRecord(r["id"], r["kind"], r["content"], r["tags"].split() if r["tags"] else [], r["source"],
                            r["source_type"], r["trust"], r["agent_id"], r["mission_id"], r["created"], r["status"],
                            json.loads(r["findings"]), score)

    def get(self, mid: str) -> Optional[MemoryRecord]:
        rows = self._q("SELECT * FROM memories WHERE id=?", (mid,))
        return self._rec(rows[0]) if rows else None

    def search(self, query: str, k: int = 8, kinds: Optional[list[str]] = None,
               min_trust: Trust = "external") -> list[MemoryRecord]:
        """Hybrid retrieval over active memories. Rank = BM25 (+ cosine if embeddings) weighted by trust."""
        fq = _fts_query(query)
        if not fq:
            return []
        rows = self._q(
            "SELECT m.*, bm25(memories_fts) AS rank FROM memories_fts JOIN memories m ON m.rowid = memories_fts.rowid "
            "WHERE memories_fts MATCH ? AND m.status='active' ORDER BY rank LIMIT 200", (fq,))
        qv = self.embedder(query) if self.embedder else None
        out = []
        for r in rows:
            if kinds and r["kind"] not in kinds:
                continue
            if TRUST_RANK[r["trust"]] < TRUST_RANK[min_trust]:
                continue
            score = -float(r["rank"])  # bm25: lower is better
            if qv is not None and r["embedding"]:
                score = score + 5.0 * _cos(qv, _unpack(r["embedding"]))
            score *= 1.0 + 0.15 * TRUST_RANK[r["trust"]]
            out.append(self._rec(r, score))
        out.sort(key=lambda m: m.score, reverse=True)
        out = out[:k]
        for m in out:
            self._x("UPDATE memories SET uses=uses+1 WHERE id=?", (m.id,))
        return out

    def list(self, status: Optional[str] = None, limit: int = 200) -> list[MemoryRecord]:
        if status:
            rows = self._q("SELECT * FROM memories WHERE status=? ORDER BY created DESC LIMIT ?", (status, limit))
        else:
            rows = self._q("SELECT * FROM memories ORDER BY created DESC LIMIT ?", (limit,))
        return [self._rec(r) for r in rows]

    # admin-path operations
    def release(self, mid: str) -> bool:
        return self._x("UPDATE memories SET status='active' WHERE id=? AND status='quarantined'", (mid,)).rowcount > 0

    def retract(self, mid: str) -> bool:
        return self._x("UPDATE memories SET status='retracted' WHERE id=?", (mid,)).rowcount > 0

    def promote(self, mid: str) -> bool:
        return self._x("UPDATE memories SET trust='verified' WHERE id=? AND status='active'", (mid,)).rowcount > 0

    def stats(self) -> dict:
        rows = self._q("SELECT kind, status, trust, count(*) AS n FROM memories GROUP BY kind, status, trust")
        eps = self._q("SELECT outcome, count(*) AS n FROM episodes GROUP BY outcome")
        return {"memories": [dict(r) for r in rows], "episodes": {r["outcome"]: r["n"] for r in eps},
                "graph_edges": self._q("SELECT count(*) AS n FROM graph")[0]["n"]}

    # ---------- knowledge graph ----------
    def relate(self, subject: str, predicate: str, obj: str, *, memory_id: Optional[str] = None,
               trust: Trust = "agent") -> None:
        if trust == "verified":
            raise PermissionError("agents cannot write verified graph edges")
        s, p, o = (x.strip().lower()[:200] for x in (subject, predicate, obj))
        if not (s and p and o):
            raise ValueError("subject, predicate and object are required")
        self._x("INSERT OR IGNORE INTO graph(subject, predicate, object, memory_id, trust, created) VALUES (?,?,?,?,?,?)",
                (s, p, o, memory_id, trust, time.time()))

    def neighbors(self, node: str, depth: int = 1, limit: int = 200) -> dict:
        node = node.strip().lower()
        seen = {node}
        frontier = {node}
        edges: list[dict] = []
        for _ in range(max(1, min(depth, 3))):
            nxt: set[str] = set()
            for n in frontier:
                for r in self._q("SELECT * FROM graph WHERE subject=? OR object=? LIMIT ?", (n, n, limit)):
                    e = {"subject": r["subject"], "predicate": r["predicate"], "object": r["object"], "trust": r["trust"]}
                    if e not in edges:
                        edges.append(e)
                    for m in (r["subject"], r["object"]):
                        if m not in seen:
                            seen.add(m)
                            nxt.add(m)
            frontier = nxt
            if len(edges) >= limit:
                break
        return {"nodes": sorted(seen), "edges": edges[:limit]}

    # ---------- episodic / experience ----------
    def record_episode(self, goal: str, steps: list[str], outcome: Literal["success", "failure"], *,
                       mission_id: Optional[str] = None, error: Optional[str] = None, agent_id: Optional[str] = None) -> str:
        if outcome not in ("success", "failure"):
            raise ValueError("outcome must be success or failure")
        eid = "ep_" + secrets.token_hex(8)
        self._x("INSERT INTO episodes(id, mission_id, goal, steps, outcome, error, agent_id, created) VALUES (?,?,?,?,?,?,?,?)",
                (eid, mission_id, goal, json.dumps(steps), outcome, error, agent_id, time.time()))
        if outcome == "success":
            # A successful workflow becomes reusable procedural memory.
            self.write(f"Goal: {goal}\nWorked: " + " -> ".join(steps), "procedural", source=f"episode:{eid}",
                       source_type="episode", trust="agent", agent_id=agent_id, mission_id=mission_id)
        return eid

    def resolve_failure(self, episode_id: str, resolution: str) -> bool:
        """Record what fixed a failure; the fix becomes procedural memory linked to the failure."""
        rows = self._q("SELECT * FROM episodes WHERE id=? AND outcome='failure'", (episode_id,))
        if not rows:
            return False
        self._x("UPDATE episodes SET resolution=? WHERE id=?", (resolution, episode_id))
        self.write(f"Failure: {rows[0]['error']}\nWhile: {rows[0]['goal']}\nFix: {resolution}", "procedural",
                   source=f"episode:{episode_id}", source_type="episode", trust="agent")
        return True

    def lessons(self, goal: str, k: int = 5) -> dict:
        """What past experience says about a new goal: procedures that worked and failures to avoid."""
        fq = _fts_query(goal)
        if not fq:
            return {"worked": [], "failed": []}
        rows = self._q("SELECT e.*, bm25(episodes_fts) AS rank FROM episodes_fts JOIN episodes e ON e.rowid=episodes_fts.rowid "
                       "WHERE episodes_fts MATCH ? ORDER BY rank LIMIT ?", (fq, k * 4))
        worked, failed = [], []
        for r in rows:
            item = {"episode_id": r["id"], "goal": r["goal"], "steps": json.loads(r["steps"])}
            if r["outcome"] == "success" and len(worked) < k:
                worked.append(item)
            elif r["outcome"] == "failure" and len(failed) < k:
                failed.append({**item, "error": r["error"], "resolution": r["resolution"]})
        return {"worked": worked, "failed": failed}

    def failure_patterns(self, limit: int = 20) -> list[dict]:
        """Recurring unresolved errors (same error text), most frequent first: input for improvement work."""
        rows = self._q("SELECT error, count(*) AS n, max(created) AS last FROM episodes WHERE outcome='failure' "
                       "AND resolution IS NULL AND error IS NOT NULL GROUP BY error ORDER BY n DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows]
