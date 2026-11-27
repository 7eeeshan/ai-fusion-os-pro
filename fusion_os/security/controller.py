"""Security controller: the single gate every agent action passes through.

Order of checks for each request: emergency stop -> agent identity/zone -> policy (immutable rules first) ->
engagement scope (for active security work) -> mission budget -> human approval. Every decision is written to the
hash-chained audit log. Ordinary agents only ever hold an agent token; admin operations need the admin token.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from .. import paths
from .approvals import ApprovalQueue
from .audit import AuditLog
from .budgets import Budgets
from .engagements import Engagement, EngagementRegistry
from .policy import ZONES, ActionRequest, Decision, PolicyEngine
from .store import Store


@dataclass
class Verdict:
    allowed: bool
    effect: str  # allow | deny | pending_approval
    reason: str
    rule_id: str
    approval_id: Optional[str] = None
    audit_seq: Optional[int] = None

    def to_dict(self) -> dict:
        return asdict(self)


def _hash_token(tok: str) -> str:
    return hashlib.sha256(tok.encode()).hexdigest()


class SecurityController:
    def __init__(self, directory: Optional[Path] = None):
        self.dir = directory or paths.security_dir()
        self.dir.mkdir(parents=True, exist_ok=True)
        self.store = Store(self.dir / "security.db")
        self.audit = AuditLog(self.store)
        self.policy = PolicyEngine(self.dir / "policy.json", self.dir / "policy.lock")
        self.approvals = ApprovalQueue(self.store)
        self.engagements = EngagementRegistry(self.store)
        self.budgets = Budgets(self.store)
        self._stop_file = self.dir / "EMERGENCY_STOP"
        self._admin_file = self.dir / "admin_token"
        env_token = os.environ.get("FUSION_OS_ADMIN_TOKEN", "").strip()
        if env_token:
            # Hosts with no persistent disk (e.g. serverless) supply a fixed admin token instead of a generated one.
            if len(env_token) < 32:
                raise ValueError("FUSION_OS_ADMIN_TOKEN must be at least 32 characters")
            paths.write_private(self._admin_file, env_token)
        elif not self._admin_file.exists():
            paths.write_private(self._admin_file, "fos_admin_" + secrets.token_urlsafe(32))
        if self.policy.upgraded_from:
            self.audit.append("system", "policy.default_upgrade", {"from": self.policy.upgraded_from, "to": self.policy.current_hash()})
        self.audit.append("system", "controller.start", {"policy_ok": self.policy.doc is not None,
                                                          "policy_error": self.policy.integrity_error})

    # ---------- identities ----------
    def admin_token(self) -> str:
        return self._admin_file.read_text(encoding="utf-8").strip()

    def is_admin(self, token: Optional[str]) -> bool:
        return bool(token) and hmac.compare_digest(token.encode(), self.admin_token().encode())

    def register_agent(self, agent_id: str, zones: list[str]) -> str:
        bad = [z for z in zones if z not in ZONES]
        if bad or not zones:
            raise ValueError(f"invalid zones {bad}; choose from {ZONES}")
        if "darkweb" in zones and len(zones) > 1:
            # Isolation: a dark-web research identity never shares an identity with any other zone.
            raise ValueError("a darkweb agent must hold only the darkweb zone")
        tok = "fos_agent_" + secrets.token_urlsafe(32)
        self.store.execute(
            "INSERT INTO agents(agent_id, token_hash, zones, created) VALUES (?,?,?,?) "
            "ON CONFLICT(agent_id) DO UPDATE SET token_hash=excluded.token_hash, zones=excluded.zones, revoked=0",
            (agent_id, _hash_token(tok), json.dumps(zones), time.time()),
        )
        self.audit.append("admin", "agent.register", {"agent_id": agent_id, "zones": zones})
        return tok

    def revoke_agent(self, agent_id: str) -> bool:
        ok = self.store.execute("UPDATE agents SET revoked=1 WHERE agent_id=?", (agent_id,)).rowcount > 0
        self.audit.append("admin", "agent.revoke", {"agent_id": agent_id, "ok": ok})
        return ok

    def agent_for_token(self, token: Optional[str]) -> Optional[dict]:
        if not token:
            return None
        rows = self.store.query("SELECT agent_id, zones FROM agents WHERE token_hash=? AND revoked=0",
                                (_hash_token(token),))
        if not rows:
            return None
        return {"agent_id": rows[0]["agent_id"], "zones": json.loads(rows[0]["zones"])}

    def list_agents(self) -> list[dict]:
        return [{"agent_id": r["agent_id"], "zones": json.loads(r["zones"]), "revoked": bool(r["revoked"]),
                 "created": r["created"]} for r in self.store.query("SELECT * FROM agents ORDER BY created")]

    # ---------- emergency stop ----------
    @property
    def stopped(self) -> bool:
        return self._stop_file.exists()

    def emergency_stop(self, by: str, reason: str) -> None:
        paths.write_private(self._stop_file, json.dumps({"by": by, "reason": reason, "at": time.time()}))
        self.audit.append(by, "emergency.stop", {"reason": reason})

    def resume(self, by: str) -> None:
        self._stop_file.unlink(missing_ok=True)
        self.audit.append(by, "emergency.resume", {})

    # ---------- the gate ----------
    def authorize(self, req: ActionRequest, agent: Optional[dict] = None) -> Verdict:
        """Decide one action. `agent` is the authenticated identity; req.agent_id must match it."""
        v = self._decide(req, agent)
        entry = self.audit.append(req.agent_id, "action." + v.effect, {
            "action": req.action, "zone": req.zone, "mission_id": req.mission_id,
            "engagement_id": req.engagement_id, "target": req.target, "rule": v.rule_id, "reason": v.reason,
            "approval_id": v.approval_id, "params": req.params,
        })
        v.audit_seq = entry["seq"]
        return v

    def _decide(self, req: ActionRequest, agent: Optional[dict]) -> Verdict:
        if self.stopped:
            return Verdict(False, "deny", "emergency stop is active", "emergency-stop")
        if agent is not None:
            if agent["agent_id"] != req.agent_id:
                return Verdict(False, "deny", "agent_id does not match the authenticated agent", "identity")
            if req.zone not in agent["zones"]:
                return Verdict(False, "deny", f"agent is not permitted in zone '{req.zone}'", "identity")
        d: Decision = self.policy.evaluate(req)
        if d.effect == "deny":
            return Verdict(False, "deny", d.reason, d.rule_id)
        if d.requires_engagement:
            ok, why = self.engagements.check(req.engagement_id, req.target, str(req.params.get("tool", "")))
            if not ok:
                return Verdict(False, "deny", why, d.rule_id)
        if req.mission_id:
            ok, why = self.budgets.check(req.mission_id, req.est_calls, req.est_seconds, req.est_usd)
            if not ok:
                return Verdict(False, "deny", why, "budget")
        if d.effect == "require_approval":
            fp = req.fingerprint()
            if req.approval_id:
                ok, why = self.approvals.consume(req.approval_id, fp)
                if not ok:
                    return Verdict(False, "deny", why, d.rule_id, req.approval_id)
            else:
                ttl = self.policy.doc.approval_ttl_seconds if self.policy.doc else 3600
                aid = self.approvals.request(req.agent_id, req.action, fp, req.model_dump(), req.justification or d.reason, ttl)
                return Verdict(False, "pending_approval", "a human must approve this action", d.rule_id, aid)
        # allowed: account for it
        if req.mission_id:
            self.budgets.record(req.mission_id, req.est_calls, req.est_seconds, req.est_usd)
        if d.requires_engagement and req.engagement_id:
            self.engagements.consume(req.engagement_id)
        return Verdict(True, "allow", d.reason, d.rule_id, req.approval_id)

    def record_usage(self, mission_id: str, seconds: float = 0, usd: float = 0) -> None:
        """Record measured cost after an action ran (on top of the estimate charged at authorization)."""
        self.budgets.record(mission_id, 0, seconds, usd)

    # ---------- admin operations ----------
    def decide_approval(self, approval_id: str, approve: bool, by: str, note: str = "") -> bool:
        ok = self.approvals.decide(approval_id, approve, by, note)
        self.audit.append(by, "approval." + ("approve" if approve else "deny"), {"approval_id": approval_id, "ok": ok, "note": note})
        return ok

    def create_engagement(self, eng: Engagement, by: str) -> Engagement:
        self.engagements.create(eng)
        self.audit.append(by, "engagement.create", eng.model_dump())
        return eng

    def revoke_engagement(self, eng_id: str, by: str) -> bool:
        ok = self.engagements.revoke(eng_id)
        self.audit.append(by, "engagement.revoke", {"id": eng_id, "ok": ok})
        return ok

    def install_policy(self, text: str, by: str) -> str:
        msg = self.policy.install(text)
        self.audit.append(by, "policy.install", {"sha256": self.policy.current_hash()})
        return msg

    def status(self) -> dict:
        return {
            "emergency_stop": self.stopped,
            "policy_ok": self.policy.doc is not None,
            "policy_error": self.policy.integrity_error,
            "policy_version": self.policy.doc.version if self.policy.doc else None,
            "policy_sha256": self.policy.current_hash(),
            "pending_approvals": len(self.approvals.list("pending")),
            "audit": self.audit.verify(),
        }
