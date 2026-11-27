"""Continuous health monitoring, failure diagnosis and safe self-healing."""
from __future__ import annotations

import shutil
import sqlite3
import time
from typing import Any, Optional


class HealthMonitor:
    def __init__(self, ctl: Any, memory: Any = None, missions: Any = None, sandbox: Any = None, engine: Any = None,
                 llm: Any = None, data_dir: Any = None):
        self.ctl, self.mem, self.missions, self.sandbox, self.engine, self.llm, self.data_dir = \
            ctl, memory, missions, sandbox, engine, llm, data_dir
        self.history: list[dict] = []

    def check(self) -> dict:
        c: dict[str, dict] = {}
        c["policy"] = {"ok": self.ctl.policy.verify(), "detail": self.ctl.policy.integrity_error or "pinned and valid"}
        a = self.ctl.audit.verify()
        c["audit_chain"] = {"ok": a["ok"], "detail": a}
        try:
            r = self.ctl.store.query("PRAGMA integrity_check")[0][0]
            c["security_db"] = {"ok": r == "ok", "detail": r}
        except sqlite3.Error as exc:
            c["security_db"] = {"ok": False, "detail": str(exc)}
        c["emergency_stop"] = {"ok": not self.ctl.stopped, "detail": "active" if self.ctl.stopped else "off"}
        if self.sandbox is not None:
            ok, d = self.sandbox.available()
            c["sandbox"] = {"ok": ok, "detail": d}
        if self.engine is not None:
            st = self.engine.status()
            c["engine_link"] = {"ok": st["connected"], "detail": st.get("error") or st.get("url"), "optional": True}
        if self.data_dir is not None:
            du = shutil.disk_usage(self.data_dir)
            c["disk"] = {"ok": du.free > 1_000_000_000, "detail": f"{du.free / 1e9:.1f} GB free"}
        if self.missions is not None:
            stuck = [m["id"] for m in self.missions.list() if m["status"] in ("running", "planning")
                     and time.time() - m["updated"] > self.missions.limits.max_seconds]
            c["missions"] = {"ok": not stuck, "detail": {"stuck": stuck}}
        overall = all(v["ok"] for v in c.values() if not v.get("optional"))
        res = {"ok": overall, "checked_at": time.time(), "checks": c}
        self.history = (self.history + [{"t": res["checked_at"], "ok": overall,
                                         "failing": [k for k, v in c.items() if not v["ok"]]}])[-500:]
        return res

    def diagnose(self) -> dict:
        h = self.check()
        advice = []
        fails = {k: v for k, v in h["checks"].items() if not v["ok"]}
        if "policy" in fails:
            advice.append("Policy file failed its integrity check: re-install the intended policy through the admin API.")
        if "audit_chain" in fails:
            advice.append("Audit chain is broken: treat as a security incident, keep the database for forensics, restore a backup.")
        if "sandbox" in fails:
            advice.append("Sandbox unavailable: start Docker Desktop. Tool, skill and research runs refuse until then.")
        if "engine_link" in fails:
            advice.append("AI Fusion Engine Pro not reachable: missions fall back to the next model provider if configured.")
        if "disk" in fails:
            advice.append("Low disk space: prune old backups and Docker images.")
        recurring = self.mem.failure_patterns() if self.mem is not None else []
        for r in recurring[:5]:
            if r["n"] >= 2:
                advice.append(f"Recurring mission failure ({r['n']}x): {r['error'][:160]}. Propose a fix in the improvement lab.")
        return {"health": h, "advice": advice, "recurring_failures": recurring}

    def heal(self, by: str = "health-monitor") -> list[str]:
        """Safe, non-privileged repairs only. Never touches policy, permissions or code."""
        done = []
        if self.missions is not None:
            for m in self.missions.list():
                if m["status"] in ("running", "planning") and time.time() - m["updated"] > self.missions.limits.max_seconds:
                    self.missions._upd(m["id"], status="failed", error="marked failed by health monitor: no progress")
                    done.append(f"closed stuck mission {m['id']}")
        if self.ctl.policy.doc is None:
            self.ctl.policy.reload()  # re-reads the pinned policy; does not bypass the integrity check
            if self.ctl.policy.doc is not None:
                done.append("policy reloaded")
        if done:
            self.ctl.audit.append(by, "health.heal", {"actions": done})
        return done
