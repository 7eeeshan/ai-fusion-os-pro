"""Technology registry: available -> evaluated -> approved | rejected -> deprecated."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Optional

CRITERIA = ("functionality", "reliability", "security", "licensing", "hardware", "compatibility", "performance",
            "cost", "maintenance", "integration")
STATUSES = ("available", "evaluated", "approved", "rejected", "deprecated")


class TechRegistry:
    def __init__(self, path: Path):
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("CREATE TABLE IF NOT EXISTS tech (id TEXT PRIMARY KEY, kind TEXT, name TEXT, source TEXT, url TEXT, "
                          "version TEXT, license TEXT, status TEXT, scores TEXT, facts TEXT, notes TEXT, discovered REAL, updated REAL)")

    @staticmethod
    def make_id(kind: str, name: str) -> str:
        return "tech_" + hashlib.sha256(f"{kind}:{name}".lower().encode()).hexdigest()[:14]

    def upsert(self, kind: str, name: str, source: str, url: str, version: str = "", license: str = "",
               facts: Optional[dict] = None) -> tuple[str, bool]:
        """Insert or refresh. Returns (id, is_new_or_new_version). A new version of an approved item goes back to
        'available' for re-evaluation, so upgrades are never adopted silently."""
        tid = self.make_id(kind, name)
        now = time.time()
        with self.lock:
            r = self.conn.execute("SELECT version, status FROM tech WHERE id=?", (tid,)).fetchone()
            if r is None:
                self.conn.execute("INSERT INTO tech VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                  (tid, kind, name, source, url, version, license, "available", "{}", json.dumps(facts or {}), "", now, now))
                return tid, True
            changed = bool(version) and version != r["version"]
            status = "available" if changed and r["status"] in ("evaluated", "approved") else r["status"]
            self.conn.execute("UPDATE tech SET version=?, license=COALESCE(NULLIF(?,''), license), facts=?, status=?, updated=? WHERE id=?",
                              (version or r["version"], license, json.dumps(facts or {}), status, now, tid))
            return tid, changed

    def set_scores(self, tid: str, scores: dict[str, Optional[float]], notes: str = "") -> None:
        clean = {k: (None if v is None else max(0.0, min(10.0, float(v)))) for k, v in scores.items() if k in CRITERIA}
        with self.lock:
            r = self.conn.execute("SELECT scores, status FROM tech WHERE id=?", (tid,)).fetchone()
            merged = {**json.loads(r["scores"]), **clean}
            st = "evaluated" if r["status"] == "available" else r["status"]
            self.conn.execute("UPDATE tech SET scores=?, notes=?, status=?, updated=? WHERE id=?",
                              (json.dumps(merged), notes, st, time.time(), tid))

    def set_status(self, tid: str, status: str) -> bool:
        if status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        return self.conn.execute("UPDATE tech SET status=?, updated=? WHERE id=?", (status, time.time(), tid)).rowcount > 0

    def list(self, status: Optional[str] = None, kind: Optional[str] = None) -> list[dict[str, Any]]:
        q, p = "SELECT * FROM tech WHERE 1=1", []
        if status:
            q += " AND status=?"
            p.append(status)
        if kind:
            q += " AND kind=?"
            p.append(kind)
        out = []
        for r in self.conn.execute(q + " ORDER BY updated DESC LIMIT 500", p):
            d = dict(r)
            d["scores"] = json.loads(d["scores"])
            d["facts"] = json.loads(d["facts"])
            known = [v for v in d["scores"].values() if v is not None]
            d["overall"] = round(sum(known) / len(known), 2) if known else None
            d["unscored"] = [c for c in CRITERIA if d["scores"].get(c) is None]
            out.append(d)
        return out
