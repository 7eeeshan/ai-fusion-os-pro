"""Security operations: authorized scans, code and malware analysis, findings management, defensive alert ingest and
reports. Every tool run is authorized by the security controller first (engagement scope for active testing)."""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any, Optional

from ..sandbox import DockerSandbox, SandboxSpec
from ..security.controller import SecurityController
from ..security.engagements import normalize_target
from ..security.policy import ActionRequest
from .tools import ADAPTERS, SEVERITIES

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, engagement_id TEXT, run_id TEXT NOT NULL, tool TEXT NOT NULL, target TEXT NOT NULL,
  title TEXT NOT NULL, severity TEXT NOT NULL, evidence TEXT NOT NULL, remediation TEXT NOT NULL, owasp TEXT,
  attack TEXT, reference TEXT, status TEXT NOT NULL DEFAULT 'open', created REAL NOT NULL, updated REAL NOT NULL,
  fingerprint TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS f_eng ON findings(engagement_id);
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY, engagement_id TEXT, tool TEXT, target TEXT, agent_id TEXT, started REAL, duration REAL,
  exit_code INTEGER, output_sha256 TEXT, findings INTEGER, verdict TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY, source TEXT, ts TEXT, signature TEXT, severity TEXT, src TEXT, dest TEXT, category TEXT,
  raw TEXT, attack TEXT
);
"""
STATUSES = ("open", "verified", "fixed", "false_positive", "accepted_risk")
SURICATA_SEV = {1: "high", 2: "medium", 3: "low"}


class SecOpsService:
    def __init__(self, ctl: SecurityController, db: Path, analysis_root: Path, docker_bin: Optional[str] = None):
        self.ctl = ctl
        self.root = analysis_root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.docker_bin = docker_bin
        self.conn = sqlite3.connect(str(db), check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.lock = threading.RLock()

    def tools(self) -> list[dict]:
        return [{"name": a.name, "image": a.image, "kind": a.kind, "action": a.action, "network": a.network, "note": a.note}
                for a in ADAPTERS.values()]

    def _sandbox(self, image: str) -> DockerSandbox:
        return DockerSandbox(allowed_images=(image,), docker_bin=self.docker_bin, workroot=self.root)

    def run_tool(self, agent: dict, tool: str, *, target: str = "", engagement_id: Optional[str] = None,
                 folder: Optional[str] = None, options: Optional[dict] = None, approval_id: Optional[str] = None,
                 action_override: Optional[str] = None, timeout_s: float = 900) -> dict:
        ad = ADAPTERS.get(tool)
        if not ad:
            raise ValueError(f"unknown tool {tool!r}")
        options = options or {}
        action = action_override or ad.action
        req = ActionRequest(agent_id=agent["agent_id"], action=action, zone="security", engagement_id=engagement_id,
                            target=target or folder, params={"tool": tool, "options": options}, approval_id=approval_id,
                            est_seconds=0)
        v = self.ctl.authorize(req, agent)
        if not v.allowed:
            return {"verdict": v.to_dict(), "run": None, "findings": []}
        workdir = None
        if ad.kind in ("code", "malware"):
            if not folder:
                raise ValueError("this tool needs an analysis folder")
            p = (self.root / folder).resolve()
            if not p.is_relative_to(self.root) or not p.is_dir():
                raise ValueError("folder must be an existing folder inside the analysis root")
            workdir = str(p)
            target = target or folder
        else:
            target = normalize_target(target) if "://" not in target else target
        spec = SandboxSpec(image=ad.image, command=ad.build(target, options), network=ad.network, timeout_s=timeout_s,
                           memory_mb=int(options.get("memory_mb", 1024)), cpus=1.0, workdir=workdir, env=ad.env or {})
        res = self._sandbox(ad.image).run(spec)
        findings = ad.parse(res.stdout, target)
        run_id = "run_" + secrets.token_hex(6)
        out_hash = hashlib.sha256(res.stdout.encode()).hexdigest()
        with self.lock:
            self.conn.execute("INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                              (run_id, engagement_id, tool, target, agent["agent_id"], time.time(), res.duration_s,
                               res.exit_code, out_hash, len(findings), json.dumps(v.to_dict())))
            for f in findings:
                fp = hashlib.sha256(f"{engagement_id}|{tool}|{f['target']}|{f['title']}".encode()).hexdigest()
                row = self.conn.execute("SELECT id FROM findings WHERE fingerprint=?", (fp,)).fetchone()
                if row:  # seen before: refresh evidence, keep triage status
                    self.conn.execute("UPDATE findings SET evidence=?, updated=?, run_id=? WHERE id=?",
                                      (f["evidence"], time.time(), run_id, row["id"]))
                    continue
                self.conn.execute(
                    "INSERT INTO findings(id, engagement_id, run_id, tool, target, title, severity, evidence, remediation, "
                    "owasp, attack, reference, created, updated, fingerprint) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    ("fnd_" + secrets.token_hex(6), engagement_id, run_id, tool, f["target"], f["title"], f["severity"],
                     f["evidence"], f["remediation"], f["owasp"], f["attack"], f["reference"], time.time(), time.time(), fp))
        self.ctl.audit.append(agent["agent_id"], "secops.run", {"run_id": run_id, "tool": tool, "target": target,
                                                                "engagement_id": engagement_id, "exit_code": res.exit_code,
                                                                "output_sha256": out_hash, "findings": len(findings)})
        return {"verdict": v.to_dict(), "run": {"id": run_id, "exit_code": res.exit_code, "duration_s": res.duration_s,
                                                "timed_out": res.timed_out, "stderr": res.stderr[-1500:], "output_sha256": out_hash},
                "findings": findings}

    def verify_finding(self, agent: dict, finding_id: str, approval_id: Optional[str] = None) -> dict:
        """Authorized verification test: re-run the detecting tool against the finding's target. Needs approval."""
        f = self.get_finding(finding_id)
        if not f:
            raise KeyError("finding not found")
        host = f["target"].rsplit(":", 1)[0] if f["tool"] == "nmap" else f["target"]
        opts = {"ports": f["target"].rsplit(":", 1)[1]} if f["tool"] == "nmap" and ":" in f["target"] else {}
        r = self.run_tool(agent, f["tool"], target=host, engagement_id=f["engagement_id"], options=opts,
                          approval_id=approval_id, action_override="security.exploit.verify")
        if r["run"] is not None:
            still = any(x["title"] == f["title"] for x in r["findings"])
            self.set_status(finding_id, "verified" if still else "fixed", agent["agent_id"])
            r["still_present"] = still
        return r

    # ---------- vulnerability management ----------
    def findings(self, engagement_id: Optional[str] = None, status: Optional[str] = None) -> list[dict]:
        sql, p = "SELECT * FROM findings WHERE 1=1", []
        if engagement_id:
            sql += " AND engagement_id=?"
            p.append(engagement_id)
        if status:
            sql += " AND status=?"
            p.append(status)
        rows = [dict(r) for r in self.conn.execute(sql, p)]
        return sorted(rows, key=lambda r: (-SEVERITIES.index(r["severity"]), r["created"]))

    def get_finding(self, fid: str) -> Optional[dict]:
        r = self.conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
        return dict(r) if r else None

    def set_status(self, fid: str, status: str, by: str) -> bool:
        if status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        ok = self.conn.execute("UPDATE findings SET status=?, updated=? WHERE id=?", (status, time.time(), fid)).rowcount > 0
        self.ctl.audit.append(by, "finding.status", {"id": fid, "status": status})
        return ok

    def runs(self, engagement_id: Optional[str] = None) -> list[dict]:
        if engagement_id:
            return [dict(r) for r in self.conn.execute("SELECT * FROM runs WHERE engagement_id=? ORDER BY started DESC", (engagement_id,))]
        return [dict(r) for r in self.conn.execute("SELECT * FROM runs ORDER BY started DESC LIMIT 200")]

    # ---------- defensive monitoring ----------
    def ingest_suricata(self, eve_lines: str) -> int:
        """Ingest Suricata EVE JSON alerts (one JSON object per line)."""
        n = 0
        for line in eve_lines.splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("event_type") != "alert":
                continue
            a = e.get("alert", {})
            aid = hashlib.sha256(line.encode()).hexdigest()[:24]
            attack = ",".join((a.get("metadata") or {}).get("mitre_technique_id", []))
            with self.lock:
                cur = self.conn.execute("INSERT OR IGNORE INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?)", (
                    aid, "suricata", e.get("timestamp"), a.get("signature"), SURICATA_SEV.get(a.get("severity"), "info"),
                    f"{e.get('src_ip')}:{e.get('src_port')}", f"{e.get('dest_ip')}:{e.get('dest_port')}", a.get("category"),
                    line[:4000], attack))
            n += cur.rowcount
        return n

    def alerts(self, limit: int = 200) -> dict:
        rows = [dict(r) for r in self.conn.execute("SELECT id, source, ts, signature, severity, src, dest, category, attack "
                                                   "FROM alerts ORDER BY ts DESC LIMIT ?", (limit,))]
        return {"alerts": rows, "by_severity": Counter(r["severity"] for r in rows),
                "top_signatures": Counter(r["signature"] for r in rows).most_common(10),
                "top_sources": Counter(r["src"].rsplit(":", 1)[0] for r in rows).most_common(10)}

    # ---------- reporting ----------
    def report(self, engagement_id: str) -> str:
        eng = self.ctl.engagements.get(engagement_id)
        if eng is None:
            raise KeyError("engagement not found or revoked")
        fs = self.findings(engagement_id)
        counts = Counter(f["severity"] for f in fs)
        runs = self.runs(engagement_id)
        L = [f"# Security assessment report: {eng.name}", "",
             f"Generated {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())} by AI Fusion OS Pro.", "",
             "## Authorization and scope", "",
             f"- Authorized by: {eng.authorized_by} (reference: {eng.authorization_ref})",
             f"- Window: {time.strftime('%Y-%m-%d %H:%M', time.gmtime(eng.starts_at))} to {time.strftime('%Y-%m-%d %H:%M', time.gmtime(eng.ends_at))} UTC",
             f"- In scope: {', '.join(eng.targets)}", f"- Excluded: {', '.join(eng.exclusions) or 'none'}",
             f"- Tools authorized: {', '.join(eng.allowed_tools)}", f"- Rules of engagement: {eng.rules_of_engagement or 'not specified'}", "",
             "## Methodology", "",
             "Testing followed the OWASP Web Security Testing Guide and mapped observations to MITRE ATT&CK techniques where "
             "applicable. All tools ran in isolated containers, only against in-scope targets, and every run is recorded in "
             "the tamper-evident audit log.", "",
             "## Summary", "", "| Severity | Count |", "|---|---|"]
        L += [f"| {s.capitalize()} | {counts.get(s, 0)} |" for s in reversed(SEVERITIES)]
        L += ["", f"Tool runs: {len(runs)}. Open findings: {sum(1 for f in fs if f['status'] == 'open')}.", "", "## Findings", ""]
        for i, f in enumerate(fs, 1):
            L += [f"### {i}. {f['title']}", "",
                  f"- Severity: **{f['severity'].upper()}** · Status: {f['status']} · Tool: {f['tool']} · Target: `{f['target']}`"]
            if f["owasp"]:
                L.append(f"- OWASP: {f['owasp']}")
            if f["attack"]:
                L.append(f"- MITRE ATT&CK: {f['attack']}")
            if f["reference"]:
                L.append(f"- References: {f['reference']}")
            L += ["", "Evidence:", "", "```", f["evidence"][:2000], "```", "", f"Remediation: {f['remediation']}", "",
                  f"Verification test: re-run `{f['tool']}` against `{f['target']}` through the approval workflow "
                  f"(finding id `{f['id']}`); the finding is marked fixed when it no longer appears.", ""]
        if not fs:
            L += ["No findings were recorded.", ""]
        L += ["## Evidence integrity", "", "| Run | Tool | Target | Exit | Output SHA-256 |", "|---|---|---|---|---|"]
        L += [f"| {r['id']} | {r['tool']} | {r['target']} | {r['exit_code']} | `{r['output_sha256'][:16]}…` |" for r in runs]
        audit = self.ctl.audit.verify()
        L += ["", f"Audit log chain verified: {audit['ok']} ({audit['entries']} entries)."]
        return "\n".join(L)
