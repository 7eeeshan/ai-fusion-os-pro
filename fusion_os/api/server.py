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

from .. import paths
from ..engine_link import EngineLink
from ..llm import Router
from ..memory import MemoryStore
from ..missions import MissionRunner
from ..skills import SkillManager
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


class MemoryWriteBody(BaseModel):
    agent_id: str
    zone: str = "standard"
    mission_id: Optional[str] = None
    content: str
    kind: str = "semantic"
    source: str
    source_type: str = "agent"
    trust: str = "agent"
    tags: list[str] = Field(default_factory=list)
    relations: list[tuple[str, str, str]] = Field(default_factory=list)


class EpisodeBody(BaseModel):
    agent_id: str
    zone: str = "standard"
    mission_id: Optional[str] = None
    goal: str
    steps: list[str]
    outcome: str
    error: Optional[str] = None


class ResolveBody(BaseModel):
    resolution: str


class SkillSubmitBody(BaseModel):
    files: dict[str, str]


class SkillRegisterBody(BaseModel):
    zone: str = "standard"
    approval_id: Optional[str] = None


class SkillRunBody(BaseModel):
    zone: str = "standard"
    mission_id: Optional[str] = None
    inputs: dict[str, Any] = Field(default_factory=dict)


class MissionBody(BaseModel):
    goal: str = Field(min_length=3, max_length=4000)


class ScanBody(BaseModel):
    text: str
    source: str = "unknown"
    source_type: str = "web"


def create_app(controller: Optional[SecurityController] = None, sandbox: Optional[DockerSandbox] = None,
               engine: Optional[EngineLink] = None, memory: Optional[MemoryStore] = None,
               skills: Optional[SkillManager] = None, missions: Optional[MissionRunner] = None) -> FastAPI:
    ctl = controller or SecurityController()
    sbx = sandbox or DockerSandbox()
    eng = engine or EngineLink()
    mem = memory or MemoryStore(paths.home() / "memory.db")
    skm = skills or SkillManager(ctl, paths.home() / "skills")
    mis = missions or MissionRunner(ctl, mem, Router(), paths.home() / "missions.db", skills=skm)
    app = FastAPI(title="AI Fusion OS Pro", version="0.1.0")
    app.state.controller = ctl
    app.state.missions = mis
    app.state.memory = mem
    app.state.skills = skm

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

    # ----- memory -----
    def _gate(a: dict, action: str, zone: str, mission_id: Optional[str], params: dict) -> None:
        v = ctl.authorize(ActionRequest(agent_id=a["agent_id"], action=action, zone=zone, mission_id=mission_id,
                                        params=params), a)
        if not v.allowed:
            raise HTTPException(403, {"verdict": v.to_dict()})

    @app.post("/v1/memory")
    def memory_write(body: MemoryWriteBody, a: dict = Depends(agent)):
        if body.agent_id != a["agent_id"]:
            raise HTTPException(403, "agent_id does not match token")
        _gate(a, "memory.write", body.zone, body.mission_id, {"kind": body.kind, "trust": body.trust, "source": body.source})
        try:
            rec = mem.write(body.content, body.kind, source=body.source, source_type=body.source_type,  # type: ignore[arg-type]
                            trust=body.trust, agent_id=a["agent_id"], mission_id=body.mission_id, tags=body.tags)  # type: ignore[arg-type]
            for s_, p_, o_ in body.relations:
                mem.relate(s_, p_, o_, memory_id=rec.id, trust="external" if body.trust == "external" else "agent")
        except (ValueError, PermissionError) as exc:
            raise HTTPException(400, str(exc))
        if rec.status == "quarantined":
            ctl.audit.append(a["agent_id"], "memory.quarantine", {"id": rec.id, "findings": rec.findings})
        return rec.to_dict()

    @app.get("/v1/memory/search")
    def memory_search(q: str, k: int = 8, kind: Optional[str] = None, zone: str = "standard",
                      a: dict = Depends(agent)):
        _gate(a, "memory.read", zone, None, {"q": q[:200]})
        recs = mem.search(q, k=min(k, 50), kinds=[kind] if kind else None)
        return [{**r.to_dict(), "prompt": r.for_prompt()} for r in recs]

    @app.get("/v1/memory/graph")
    def memory_graph(node: str, depth: int = 1, zone: str = "standard", a: dict = Depends(agent)):
        _gate(a, "memory.read", zone, None, {"node": node[:200]})
        return mem.neighbors(node, depth)

    @app.post("/v1/episodes")
    def episode(body: EpisodeBody, a: dict = Depends(agent)):
        _gate(a, "memory.write", body.zone, body.mission_id, {"kind": "episodic"})
        try:
            return {"id": mem.record_episode(body.goal, body.steps, body.outcome, mission_id=body.mission_id,  # type: ignore[arg-type]
                                             error=body.error, agent_id=a["agent_id"])}
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.post("/v1/episodes/{episode_id}/resolve")
    def resolve(episode_id: str, body: ResolveBody, a: dict = Depends(agent)):
        _gate(a, "memory.write", "standard" if "standard" in a["zones"] else a["zones"][0], None, {"kind": "procedural"})
        if not mem.resolve_failure(episode_id, body.resolution):
            raise HTTPException(404, "no such failed episode")
        return {"ok": True}

    @app.get("/v1/lessons")
    def lessons(goal: str, zone: str = "standard", a: dict = Depends(agent)):
        _gate(a, "memory.read", zone, None, {"goal": goal[:200]})
        return mem.lessons(goal)

    # ----- skills -----
    @app.get("/v1/skills")
    def skills_list(_: dict = Depends(agent)):
        return skm.list()

    @app.get("/v1/skills/match")
    def skills_match(need: str, _: dict = Depends(agent)):
        hits = skm.find_for_capability(need)
        return {"need": need, "matches": hits, "gap": not hits}

    @app.post("/v1/skills/submit")
    def skills_submit(body: SkillSubmitBody, a: dict = Depends(agent)):
        try:
            return skm.submit(body.files, a["agent_id"])
        except ValueError as exc:
            raise HTTPException(400, str(exc)[:1000])

    @app.post("/v1/skills/{name}/{version}/register")
    def skills_register(name: str, version: str, body: SkillRegisterBody, a: dict = Depends(agent)):
        try:
            return skm.register(name, version, a, body.zone, body.approval_id).to_dict()
        except KeyError as exc:
            raise HTTPException(404, str(exc))
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.post("/v1/skills/{name}/run")
    def skills_run(name: str, body: SkillRunBody, a: dict = Depends(agent)):
        try:
            return skm.run(name, body.inputs, a, body.zone, body.mission_id)
        except KeyError as exc:
            raise HTTPException(404, str(exc))
        except PermissionError as exc:
            raise HTTPException(409, str(exc))
        except SandboxUnavailable as exc:
            raise HTTPException(503, str(exc))

    # ----- admin-facing -----
    @app.get("/admin/memory", dependencies=[Depends(admin)])
    def admin_memory(status: Optional[str] = None):
        return {"stats": mem.stats(), "records": [r.to_dict() for r in mem.list(status)],
                "recurring_failures": mem.failure_patterns()}

    @app.post("/admin/memory/{mid}/{op}", dependencies=[Depends(admin)])
    def admin_memory_op(mid: str, op: str):
        fn = {"release": mem.release, "retract": mem.retract, "promote": mem.promote}.get(op)
        if fn is None:
            raise HTTPException(400, "op must be release, retract or promote")
        ok = fn(mid)
        ctl.audit.append("admin", f"memory.{op}", {"id": mid, "ok": ok})
        return {"ok": ok}

    @app.post("/admin/missions", dependencies=[Depends(admin)])
    def mission_start(body: MissionBody):
        return {"id": mis.start(body.goal, "admin")}

    @app.get("/admin/missions", dependencies=[Depends(admin)])
    def mission_list():
        return mis.list()

    @app.get("/admin/missions/{mid}", dependencies=[Depends(admin)])
    def mission_get(mid: str):
        m = mis.get(mid)
        if not m:
            raise HTTPException(404, "not found")
        return m

    @app.post("/admin/missions/{mid}/stop", dependencies=[Depends(admin)])
    def mission_stop(mid: str):
        mis.stop(mid)
        return {"ok": True}

    @app.post("/admin/missions/{mid}/resume", dependencies=[Depends(admin)])
    def mission_resume(mid: str):
        regs = mis.complete_skill_registration(mid)
        try:
            mis.resume(mid)
        except ValueError as exc:
            raise HTTPException(409, str(exc))
        return {"skills": regs}

    @app.post("/admin/skills/{name}/rollback", dependencies=[Depends(admin)])
    def admin_skill_rollback(name: str):
        try:
            return {"active": skm.rollback(name)}
        except ValueError as exc:
            raise HTTPException(400, str(exc))

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
