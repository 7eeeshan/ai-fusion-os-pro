"""Improvement lab: agents propose changes to prompts or routing; each proposal is benchmarked against the current
setting, must not regress, and is applied only after human approval (`system.update`). If the post-apply check fails,
the change is rolled back automatically."""
from __future__ import annotations

import json
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any, Callable, Optional

from ..config_store import ConfigStore
from ..security.controller import SecurityController
from ..security.policy import ActionRequest

KINDS = {"prompt", "routing", "workflow"}


class ImprovementLab:
    def __init__(self, ctl: SecurityController, cfg: ConfigStore, db: Path,
                 evaluator: Callable[[str, Any], float], post_check: Optional[Callable[[], bool]] = None):
        """evaluator(config_key, value) -> score in [0,1] measured on a benchmark with that value in effect."""
        self.ctl, self.cfg, self.evaluate, self.post_check = ctl, cfg, evaluator, post_check
        self.conn = sqlite3.connect(str(db), check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("CREATE TABLE IF NOT EXISTS proposals (id TEXT PRIMARY KEY, kind TEXT, key TEXT, value TEXT, "
                          "rationale TEXT, by TEXT, status TEXT, baseline REAL, score REAL, created REAL, updated REAL, approval_id TEXT)")

    def propose(self, kind: str, key: str, value: Any, rationale: str, by: str) -> str:
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {sorted(KINDS)}")
        if key.startswith(("policy", "security", "model.")):
            raise PermissionError("security settings and model deployments cannot be changed through proposals")
        pid = "prp_" + secrets.token_hex(6)
        self.conn.execute("INSERT INTO proposals VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                          (pid, kind, key, json.dumps(value), rationale, by, "proposed", None, None, time.time(), time.time(), None))
        self.ctl.audit.append(by, "improve.propose", {"id": pid, "key": key})
        return pid

    def get(self, pid: str) -> dict:
        r = self.conn.execute("SELECT * FROM proposals WHERE id=?", (pid,)).fetchone()
        if not r:
            raise KeyError(pid)
        return dict(r) | {"value": json.loads(r["value"])}

    def list(self) -> list[dict]:
        return [dict(r) | {"value": json.loads(r["value"])} for r in self.conn.execute("SELECT * FROM proposals ORDER BY created DESC")]

    def validate(self, pid: str) -> dict:
        p = self.get(pid)
        baseline = self.evaluate(p["key"], self.cfg.get(p["key"]))
        score = self.evaluate(p["key"], p["value"])
        status = "validated" if score >= baseline and score > 0 else "rejected"
        self.conn.execute("UPDATE proposals SET status=?, baseline=?, score=?, updated=? WHERE id=?",
                          (status, baseline, score, time.time(), pid))
        self.ctl.audit.append("improvement-lab", "improve.validate", {"id": pid, "baseline": baseline, "score": score, "status": status})
        return {"status": status, "baseline": baseline, "score": score}

    def apply(self, pid: str, agent: dict, approval_id: Optional[str] = None) -> dict:
        p = self.get(pid)
        if p["status"] != "validated":
            raise ValueError(f"proposal is {p['status']}; only validated proposals can be applied")
        v = self.ctl.authorize(ActionRequest(agent_id=agent["agent_id"], action="system.update", zone="standard",
                                             params={"proposal": pid, "key": p["key"]}, approval_id=approval_id), agent)
        if not v.allowed:
            self.conn.execute("UPDATE proposals SET approval_id=? WHERE id=?", (v.approval_id, pid))
            return v.to_dict()
        self.cfg.set(p["key"], p["value"], agent["agent_id"], f"proposal {pid}")
        if self.post_check is not None and not self.post_check():
            self.cfg.rollback(p["key"], "improvement-lab")
            self.conn.execute("UPDATE proposals SET status='rolled_back', updated=? WHERE id=?", (time.time(), pid))
            self.ctl.audit.append("improvement-lab", "improve.auto_rollback", {"id": pid})
            return v.to_dict() | {"applied": False, "rolled_back": True}
        self.conn.execute("UPDATE proposals SET status='applied', updated=? WHERE id=?", (time.time(), pid))
        self.ctl.audit.append(agent["agent_id"], "improve.apply", {"id": pid, "key": p["key"]})
        return v.to_dict() | {"applied": True}
