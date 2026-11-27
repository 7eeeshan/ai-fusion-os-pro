"""HTTP API for AI Fusion OS Pro (Phase 1: security controller, approvals, audit, engagements, sandbox).

Two kinds of bearer token:
- agent tokens (issued by the admin, bound to an agent id and its zones) can ask for decisions and run sandboxed
  commands through the gate;
- the admin token (the human operator) can approve/deny, manage engagements, agents, policy and the emergency stop.
Binds to 127.0.0.1 by default.
"""
from __future__ import annotations

import time
from typing import Any, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from ..engine_link import EngineLink
from ..sandbox import DockerSandbox, SandboxSpec, SandboxUnavailable
from ..sandbox.docker import SandboxError
from ..security.controller import SecurityController
from ..security.engagements import Engagement
from ..security.policy import ActionRequest
from ..security.untrusted import wrap


def _bearer(authorization: Optional[str]) -> Optional[str]:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


class DecisionBody(BaseModel):
    approve: bool
    note: str = ""


class AgentBody(BaseModel):
    agent_id: str = Field(pattern=r"^[a-zA-Z0-9_.-]{2,64}$")
    zones: list[str]


class BudgetBody(BaseModel):
    max_calls: int = Field(ge=0)
    max_seconds: float = Field(ge=0)
    max_usd: float = Field(ge=0)


class StopBody(BaseModel):
    reason: str = "manual"


class PolicyBody(BaseModel):
    policy_json: str


class SandboxBody(BaseModel):
    request: ActionRequest
    image: str
    command: list[str]
    network: str = "none"
    timeout_s: float = 60
    memory_mb: int = 512
    cpus: float = 1.0
    stdin: Optional[str] = None


class ScanBody(BaseModel):
    text: str
    source: str = "unknown"
    source_type: str = "web"


def create_app(controller: Optional[SecurityController] = None, sandbox: Optional[DockerSandbox] = None,
               engine: Optional[EngineLink] = None) -> FastAPI:
    ctl = controller or SecurityController()
    sbx = sandbox or DockerSandbox()
    eng = engine or EngineLink()
    app = FastAPI(title="AI Fusion OS Pro", version="0.1.0")
    app.state.controller = ctl

    def admin(authorization: Optional[str] = Header(None)) -> str:
        if not ctl.is_admin(_bearer(authorization)):
            raise HTTPException(403, "admin token required")
        return "admin"

    def agent(authorization: Optional[str] = Header(None)) -> dict:
        a = ctl.agent_for_token(_bearer(authorization))
        if a is None:
            raise HTTPException(401, "valid agent token required")
        return a

    @app.get("/health")
    def health():
        return {"ok": True, "service": "ai-fusion-os-pro", "emergency_stop": ctl.stopped}

    # ----- agent-facing -----
    @app.post("/v1/authorize")
    def authorize(req: ActionRequest, a: dict = Depends(agent)):
        return ctl.authorize(req, a).to_dict()

    @app.post("/v1/sandbox/exec")
    def sandbox_exec(body: SandboxBody, a: dict = Depends(agent)):
        req = body.request
        if req.action != "sandbox.exec":
            raise HTTPException(400, "request.action must be sandbox.exec")
        # The policy sees the real network mode and image; the agent cannot describe one thing and run another.
        req.params = {**req.params, "network": body.network, "image": body.image}
        v = ctl.authorize(req, a)
        if not v.allowed:
            return {"verdict": v.to_dict(), "result": None}
        spec = SandboxSpec(image=body.image, command=body.command, network=body.network, timeout_s=body.timeout_s,
                           memory_mb=body.memory_mb, cpus=body.cpus, stdin=body.stdin)
        try:
            res = sbx.run(spec)
        except SandboxUnavailable as exc:
            ctl.audit.append(req.agent_id, "sandbox.unavailable", {"error": str(exc)})
            raise HTTPException(503, str(exc))
        except SandboxError as exc:
            raise HTTPException(400, str(exc))
        if req.mission_id:
            ctl.record_usage(req.mission_id, seconds=res.duration_s)
        ctl.audit.append(req.agent_id, "sandbox.result", {"container": res.container, "exit_code": res.exit_code,
                                                           "timed_out": res.timed_out, "duration_s": res.duration_s})
        out = res.to_dict()
        out["stdout_wrapped"] = wrap(res.stdout, f"sandbox:{res.container}", "tool").render()
        return {"verdict": v.to_dict(), "result": out}

    @app.post("/v1/untrusted/scan")
    def scan(body: ScanBody, _: dict = Depends(agent)):
        c = wrap(body.text, body.source, body.source_type)
        return {**c.to_dict(), "rendered": c.render()}

    @app.get("/v1/approvals/{approval_id}")
    def approval_status(approval_id: str, a: dict = Depends(agent)):
        for r in ctl.approvals.list():
            if r["id"] == approval_id and r["agent_id"] == a["agent_id"]:
                return {"id": r["id"], "status": r["status"], "note": r["note"]}
        raise HTTPException(404, "not found")

    # ----- admin-facing -----
    @app.get("/admin/status", dependencies=[Depends(admin)])
    def status():
        return {**ctl.status(), "sandbox": dict(zip(("available", "detail"), sbx.available())),
                "engine_link": eng.status()}

    @app.get("/admin/approvals", dependencies=[Depends(admin)])
    def approvals(status: Optional[str] = None):
        return ctl.approvals.list(status)

    @app.post("/admin/approvals/{approval_id}", dependencies=[Depends(admin)])
    def decide(approval_id: str, body: DecisionBody):
        if not ctl.decide_approval(approval_id, body.approve, "admin", body.note):
            raise HTTPException(409, "approval not pending (already decided, used or expired)")
        return {"ok": True}

    @app.get("/admin/audit", dependencies=[Depends(admin)])
    def audit(limit: int = 200, after_seq: int = 0, event_prefix: str = ""):
        return ctl.audit.entries(limit, after_seq, event_prefix)

    @app.get("/admin/audit/verify", dependencies=[Depends(admin)])
    def audit_verify():
        return ctl.audit.verify()

    @app.get("/admin/engagements", dependencies=[Depends(admin)])
    def engagements():
        return ctl.engagements.list()

    @app.post("/admin/engagements", dependencies=[Depends(admin)])
    def create_engagement(e: Engagement):
        return ctl.create_engagement(e, "admin").model_dump()

    @app.delete("/admin/engagements/{eng_id}", dependencies=[Depends(admin)])
    def revoke_engagement(eng_id: str):
        return {"ok": ctl.revoke_engagement(eng_id, "admin")}

    @app.get("/admin/agents", dependencies=[Depends(admin)])
    def agents():
        return ctl.list_agents()

    @app.post("/admin/agents", dependencies=[Depends(admin)])
    def register_agent(body: AgentBody):
        try:
            return {"agent_id": body.agent_id, "token": ctl.register_agent(body.agent_id, body.zones)}
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.delete("/admin/agents/{agent_id}", dependencies=[Depends(admin)])
    def revoke_agent(agent_id: str):
        return {"ok": ctl.revoke_agent(agent_id)}

    @app.get("/admin/budgets", dependencies=[Depends(admin)])
    def budgets():
        return ctl.budgets.list()

    @app.put("/admin/budgets/{mission_id}", dependencies=[Depends(admin)])
    def set_budget(mission_id: str, body: BudgetBody):
        ctl.budgets.set(mission_id, body.max_calls, body.max_seconds, body.max_usd)
        ctl.audit.append("admin", "budget.set", {"mission_id": mission_id, **body.model_dump()})
        return ctl.budgets.get(mission_id)

    @app.post("/admin/emergency-stop", dependencies=[Depends(admin)])
    def stop(body: StopBody):
        ctl.emergency_stop("admin", body.reason)
        return {"emergency_stop": True}

    @app.post("/admin/resume", dependencies=[Depends(admin)])
    def resume():
        ctl.resume("admin")
        return {"emergency_stop": False}

    @app.get("/admin/policy", dependencies=[Depends(admin)])
    def get_policy():
        return {"sha256": ctl.policy.current_hash(), "ok": ctl.policy.doc is not None,
                "error": ctl.policy.integrity_error,
                "policy": ctl.policy.doc.model_dump() if ctl.policy.doc else None}

    @app.put("/admin/policy", dependencies=[Depends(admin)])
    def put_policy(body: PolicyBody):
        try:
            return {"message": ctl.install_policy(body.policy_json, "admin"), "sha256": ctl.policy.current_hash()}
        except ValueError as exc:
            raise HTTPException(400, str(exc)[:500])

    @app.get("/admin/engine", dependencies=[Depends(admin)])
    def engine_status():
        return eng.status()

    return app
