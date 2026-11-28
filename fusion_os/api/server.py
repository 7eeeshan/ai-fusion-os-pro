"""HTTP API for AI Fusion OS Pro (Phase 1: security controller, approvals, audit, engagements, sandbox).

Two kinds of bearer token:
- agent tokens (issued by the admin, bound to an agent id and its zones) can ask for decisions and run sandboxed
  commands through the gate;
- the admin token (the human operator) can approve/deny, manage engagements, agents, policy and the emergency stop.
Binds to 127.0.0.1 by default.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from .. import paths
from ..engine_link import EngineLink
from ..llm import Router
from ..memory import MemoryStore
from ..missions import MissionRunner
from ..research import FetchBlocked, SurfaceWeb, TorResearch
from ..research.common import EvidenceStore
from ..research.tor import TorUnavailable
from ..secops import SecOpsService
from ..config_store import ConfigStore
from ..intel import TechIntelAgent, TechRegistry
from ..llm import AnthropicLLM, EngineLLM
from ..models import ModelManager
from ..models.bench import BUILTIN_SUITES, BenchmarkSuite
from ..ops import BackupManager, HealthMonitor, ImprovementLab
from ..cloud import JobQueue, Worker
from ..cloud.llm_bridge import QueueLLM
from ..skills import SkillManager
from ..sandbox import DockerSandbox, SandboxSpec, SandboxUnavailable, make_sandbox
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


class ToolRunBody(BaseModel):
    tool: str
    target: str = ""
    engagement_id: Optional[str] = None
    folder: Optional[str] = None
    options: dict[str, Any] = Field(default_factory=dict)
    approval_id: Optional[str] = None


class VerifyBody(BaseModel):
    approval_id: Optional[str] = None


class StatusBody(BaseModel):
    status: str


class FetchBody(BaseModel):
    url: str
    zone: str = "research"
    mission_id: Optional[str] = None


class PortalBody(BaseModel):
    url: str
    credential: str
    approval_id: Optional[str] = None


class TechStatusBody(BaseModel):
    status: str


class ScoresBody(BaseModel):
    scores: dict[str, Optional[float]]
    notes: str = ""


class BenchBody(BaseModel):
    provider: str
    model: str
    suite: str = "general-v1"
    cases: Optional[list[dict]] = None


class DeployBody(BaseModel):
    role: str = "default"
    provider: str
    model: str
    approval_id: Optional[str] = None


class ProposalBody(BaseModel):
    kind: str
    key: str
    value: Any
    rationale: str


class ApplyBody(BaseModel):
    approval_id: Optional[str] = None


class LeaseBody(BaseModel):
    node_id: str = Field(pattern=r"^[a-zA-Z0-9_.-]{2,64}$")
    capabilities: list[str] = Field(default_factory=list)
    location: str = "local"


class JobResultBody(BaseModel):
    node_id: str
    result: Any = None
    error: str = ""


class ScheduleBody(BaseModel):
    name: str
    kind: str
    payload: dict = Field(default_factory=dict)
    interval_s: float = Field(ge=60)
    requires: list[str] = Field(default_factory=list)


class LaunchBody(BaseModel):
    launch: str


class ScanBody(BaseModel):
    text: str
    source: str = "unknown"
    source_type: str = "web"


def create_app(controller: Optional[SecurityController] = None, sandbox: Optional[DockerSandbox] = None,
               engine: Optional[EngineLink] = None, memory: Optional[MemoryStore] = None,
               skills: Optional[SkillManager] = None, missions: Optional[MissionRunner] = None,
               secops: Optional[SecOpsService] = None, web: Optional[SurfaceWeb] = None,
               tor: Optional[TorResearch] = None, desktop: Any = None) -> FastAPI:
    ctl = controller or SecurityController()
    sbx = sandbox or make_sandbox(generic=True)
    eng = engine or EngineLink()
    mem = memory or MemoryStore(paths.home() / "memory.db")
    skm = skills or SkillManager(ctl, paths.home() / "skills")
    import os
    queue = JobQueue(paths.home() / "queue.db")
    order = [p.strip() for p in os.environ.get("FUSION_OS_LLM_ORDER", "engine,queue,anthropic").split(",") if p.strip()]
    table = {"engine": lambda: EngineLLM(eng), "queue": lambda: QueueLLM(queue), "anthropic": lambda: AnthropicLLM()}
    router = Router([table[p]() for p in order if p in table])
    mis = missions or MissionRunner(ctl, mem, router, paths.home() / "missions.db", skills=skm)
    queue_mode = os.environ.get("FUSION_OS_MISSION_MODE", "thread") == "queue"
    sec = secops or SecOpsService(ctl, paths.home() / "secops.db", paths.home() / "analysis")
    wb = web or SurfaceWeb(ctl, EvidenceStore(paths.home() / "evidence.db"), translator=Router())
    cfg = ConfigStore(paths.home() / "config.db")
    reg = TechRegistry(paths.home() / "tech.db")
    intel_box: dict = {}

    def intel() -> TechIntelAgent:
        if "a" not in intel_box:
            intel_box["a"] = TechIntelAgent(ctl, reg)
        return intel_box["a"]

    def _provider(name: str):
        if name == "engine":
            return lambda model, system, prompt: EngineLLM(eng, model).complete(system, prompt, 800)
        if name == "anthropic":
            return lambda model, system, prompt: AnthropicLLM(model=model).complete(system, prompt, 800)
        raise KeyError(name)

    mm = ModelManager(ctl, cfg, paths.home() / "bench.db", {"engine": _provider("engine"), "anthropic": _provider("anthropic")})
    ops_token = ctl.register_agent("ops-console", ["standard"])
    ops_agent = ctl.agent_for_token(ops_token)

    def _evaluate(key: str, value: Any) -> float:
        """Score a prompt setting on the general benchmark with the deployed (or first available) model."""
        dep = mm.deployed() or {"provider": "engine", "model": ""}
        suite = BUILTIN_SUITES["general-v1"]
        if key.startswith("prompt.") and isinstance(value, str):
            suite = BenchmarkSuite(suite.name, suite.cases, system=value)
        return mm.run(suite, dep["provider"], dep["model"])["accuracy"]

    # Dark-web evidence lives in its own database, apart from memory and surface research.
    tr = tor or TorResearch(ctl, EvidenceStore(paths.home() / "darkweb_evidence.db"), paths.home() / "tor", translator=Router())
    app = FastAPI(title="AI Fusion OS Pro", version="0.1.0")
    app.state.controller = ctl
    app.state.missions = mis
    app.state.memory = mem
    app.state.skills = skm
    app.state.secops = sec

    def admin(authorization: Optional[str] = Header(None)) -> str:
        if not ctl.is_admin(_bearer(authorization)):
            raise HTTPException(403, "admin token required")
        return "admin"

    def agent(authorization: Optional[str] = Header(None)) -> dict:
        a = ctl.agent_for_token(_bearer(authorization))
        if a is None:
            raise HTTPException(401, "valid agent token required")
        return a

    @app.get("/dashboard", include_in_schema=False)
    def dashboard():
        from fastapi.responses import HTMLResponse
        from importlib import resources as _r
        html = _r.files("fusion_os.api").joinpath("dashboard.html").read_text(encoding="utf-8")
        return HTMLResponse(html, headers={"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'; "
                                           "style-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'",
                                           "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"})

    if desktop is not None:
        # Desktop app only: the shell proves it can read this Windows user's private data folder by presenting the
        # per-start launch secret, and gets a dashboard session without anyone pasting the admin token.
        @app.post("/desktop/session", include_in_schema=False)
        def desktop_session(body: LaunchBody):
            if not desktop.check(body.launch):
                ctl.audit.append("desktop", "desktop.session_denied", {})
                raise HTTPException(403, "invalid launch secret")
            ctl.audit.append("desktop", "desktop.session", {})
            return {"admin_token": ctl.admin_token()}

        @app.post("/desktop/shutdown", include_in_schema=False)
        def desktop_shutdown(body: LaunchBody):
            if not desktop.check(body.launch):
                raise HTTPException(403, "invalid launch secret")
            ctl.audit.append("desktop", "desktop.shutdown", {})
            desktop.request_stop()
            return {"ok": True}

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

    health = HealthMonitor(ctl, memory=mem, missions=mis, sandbox=skm.sandbox, engine=eng, data_dir=paths.home())
    backups = BackupManager(paths.home(), ctl)
    lab = ImprovementLab(ctl, cfg, paths.home() / "proposals.db", _evaluate, post_check=lambda: health.check()["ok"])
    mis.cfg = cfg

    # ----- cloud queue -----
    handlers = {
        "mission.run": lambda p: (mis.run(p["mission_id"]), mis.get(p["mission_id"])["status"])[1],
        "techintel.scan": lambda p: intel().scan(p.get("watchlist") or cfg.get("intel.watchlist")),
        "health.heal": lambda p: health.heal(),
        "health.check": lambda p: health.check()["ok"],
        "backup.create": lambda p: backups.create(p.get("label", "scheduled"), "scheduler"),
    }
    app.state.queue = queue
    app.state.handlers = handlers
    if os.environ.get("FUSION_OS_WORKER", "0") == "1":
        caps = [c for c in os.environ.get("FUSION_OS_CAPABILITIES", "docker").split(",") if c]
        w = Worker(queue, handlers, caps, os.environ.get("FUSION_OS_LOCATION", "cloud"))
        threading.Thread(target=w.run_forever, daemon=True, name="worker").start()
        app.state.worker = w
    if os.environ.get("FUSION_OS_SCHEDULER", "0") == "1":
        queue.schedule("tech-intel-daily", "techintel.scan", {}, 86400)
        queue.schedule("health-heal-5min", "health.heal", {}, 300)
        queue.schedule("backup-daily", "backup.create", {"label": "daily"}, 86400)

        def _tick():
            while True:
                queue.tick()
                time.sleep(30)
        threading.Thread(target=_tick, daemon=True, name="scheduler").start()

    @app.post("/v1/queue/lease")
    def q_lease(body: LeaseBody, a: dict = Depends(agent)):
        return {"job": queue.lease(f"{a['agent_id']}:{body.node_id}", body.capabilities, body.location)}

    @app.post("/v1/queue/{job_id}/heartbeat")
    def q_beat(job_id: str, body: JobResultBody, a: dict = Depends(agent)):
        return {"ok": queue.heartbeat(job_id, f"{a['agent_id']}:{body.node_id}")}

    @app.post("/v1/queue/{job_id}/complete")
    def q_complete(job_id: str, body: JobResultBody, a: dict = Depends(agent)):
        return {"ok": queue.complete(job_id, f"{a['agent_id']}:{body.node_id}", body.result)}

    @app.post("/v1/queue/{job_id}/fail")
    def q_fail(job_id: str, body: JobResultBody, a: dict = Depends(agent)):
        return {"ok": queue.fail(job_id, f"{a['agent_id']}:{body.node_id}", body.error)}

    @app.get("/admin/queue", dependencies=[Depends(admin)])
    def q_overview():
        return {"stats": queue.stats(), "nodes": queue.nodes(), "recent": queue.recent(), "schedules": queue.schedules(),
                "llm_last": router.last}

    @app.post("/admin/queue/schedule", dependencies=[Depends(admin)])
    def q_schedule(body: ScheduleBody):
        if body.kind not in handlers:
            raise HTTPException(400, f"kind must be one of {sorted(handlers)}")
        queue.schedule(body.name, body.kind, body.payload, body.interval_s, body.requires)
        return {"ok": True}

    @app.get("/admin/resources", dependencies=[Depends(admin)])
    def resources():
        import psutil
        vm = psutil.virtual_memory()
        du = psutil.disk_usage(str(paths.home()))
        local = {"cpu_percent": psutil.cpu_percent(interval=0.2), "cpu_count": psutil.cpu_count(),
                 "ram_used_gb": round(vm.used / 1e9, 2), "ram_total_gb": round(vm.total / 1e9, 2), "ram_percent": vm.percent,
                 "disk_free_gb": round(du.free / 1e9, 1)}
        engine_hw = None
        if eng.status()["connected"]:
            try:
                engine_hw = eng.client.get(f"{eng.base_url}/api/hardware", headers=eng._headers(), timeout=5).json()
            except Exception as exc:
                engine_hw = {"error": str(exc)[:200]}
        return {"this_node": local, "engine": engine_hw, "nodes": queue.nodes(), "queue": queue.stats()}

    # ----- technology intelligence -----
    @app.get("/admin/intel", dependencies=[Depends(admin)])
    def intel_list(status: Optional[str] = None, kind: Optional[str] = None):
        return reg.list(status, kind)

    @app.post("/admin/intel/scan", dependencies=[Depends(admin)])
    def intel_scan(watchlist: Optional[dict] = None):
        return intel().scan(watchlist or cfg.get("intel.watchlist"))

    @app.put("/admin/intel/{tid}/status", dependencies=[Depends(admin)])
    def intel_status(tid: str, body: TechStatusBody):
        try:
            ok = reg.set_status(tid, body.status)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        ctl.audit.append("admin", "intel.status", {"id": tid, "status": body.status})
        return {"ok": ok}

    @app.put("/admin/intel/{tid}/scores", dependencies=[Depends(admin)])
    def intel_scores(tid: str, body: ScoresBody):
        reg.set_scores(tid, body.scores, body.notes)
        return {"ok": True}

    # ----- models -----
    @app.get("/admin/models", dependencies=[Depends(admin)])
    def models_overview():
        import os
        return {"deployed": mm.deployed(), "history": cfg.history("model.default"),
                "discovered": mm.discover(eng, os.environ.get("ANTHROPIC_API_KEY"), httpx.Client(timeout=15)),
                "results": mm.results(), "suites": list(BUILTIN_SUITES)}

    @app.post("/admin/models/benchmark", dependencies=[Depends(admin)])
    def models_bench(body: BenchBody):
        suite = BenchmarkSuite("custom", body.cases) if body.cases else BUILTIN_SUITES.get(body.suite)
        if suite is None:
            raise HTTPException(404, "unknown suite")
        try:
            return mm.run(suite, body.provider, body.model)
        except KeyError:
            raise HTTPException(400, "provider must be engine or anthropic")

    @app.post("/admin/models/compare", dependencies=[Depends(admin)])
    def models_compare(body: BenchBody):
        return mm.compare(BUILTIN_SUITES.get(body.suite, BUILTIN_SUITES["general-v1"]), {"provider": body.provider, "model": body.model})

    @app.post("/admin/models/deploy", dependencies=[Depends(admin)])
    def models_deploy(body: DeployBody):
        return mm.deploy(ops_agent, body.role, body.provider, body.model, body.approval_id)

    @app.post("/admin/models/rollback", dependencies=[Depends(admin)])
    def models_rollback(role: str = "default"):
        return {"deployed": mm.rollback(role)}

    # ----- health, recovery, improvement -----
    @app.get("/admin/health", dependencies=[Depends(admin)])
    def health_check():
        return health.diagnose() | {"history": health.history[-100:]}

    @app.post("/admin/health/heal", dependencies=[Depends(admin)])
    def health_heal():
        return {"actions": health.heal()}

    @app.get("/admin/backups", dependencies=[Depends(admin)])
    def backups_list():
        return backups.list()

    @app.post("/admin/backups", dependencies=[Depends(admin)])
    def backups_create(label: str = "manual"):
        return {"name": backups.create(label)}

    @app.post("/admin/backups/{name}/restore", dependencies=[Depends(admin)])
    def backups_restore(name: str):
        try:
            return backups.restore(name)
        except (FileNotFoundError, ValueError) as exc:
            raise HTTPException(400, str(exc))

    @app.get("/admin/improvements", dependencies=[Depends(admin)])
    def improvements():
        return lab.list()

    @app.post("/v1/improvements")
    def improvements_propose(body: ProposalBody, a: dict = Depends(agent)):
        try:
            return {"id": lab.propose(body.kind, body.key, body.value, body.rationale, a["agent_id"])}
        except (ValueError, PermissionError) as exc:
            raise HTTPException(400, str(exc))

    @app.post("/admin/improvements/{pid}/validate", dependencies=[Depends(admin)])
    def improvements_validate(pid: str):
        return lab.validate(pid)

    @app.post("/admin/improvements/{pid}/apply", dependencies=[Depends(admin)])
    def improvements_apply(pid: str, body: ApplyBody):
        try:
            return lab.apply(pid, ops_agent, body.approval_id)
        except ValueError as exc:
            raise HTTPException(409, str(exc))

    @app.get("/admin/config", dependencies=[Depends(admin)])
    def config_all():
        return {k: cfg.history(k)[:5] for k in cfg.keys()}

    @app.post("/admin/config/{key}/rollback", dependencies=[Depends(admin)])
    def config_rollback(key: str):
        return {"value": cfg.rollback(key, "admin")}

    # ----- research -----
    def _research(fn, *args, **kw):
        try:
            return fn(*args, **kw)
        except PermissionError as exc:
            raise HTTPException(403, exc.args[0] if exc.args else "denied")
        except (FetchBlocked, ValueError) as exc:
            raise HTTPException(400, str(exc))
        except (TorUnavailable, httpx.HTTPError) as exc:
            raise HTTPException(503, str(exc)[:500])

    @app.post("/v1/research/fetch")
    def research_fetch(body: FetchBody, a: dict = Depends(agent)):
        return _research(wb.fetch, a, body.url, body.zone, body.mission_id)

    @app.get("/v1/research/search")
    def research_search(q: str, zone: str = "research", a: dict = Depends(agent)):
        return _research(wb.search, a, q, zone)

    @app.get("/v1/research/academic")
    def research_academic(q: str, zone: str = "research", a: dict = Depends(agent)):
        return _research(wb.academic, a, q, zone)

    @app.post("/v1/research/portal")
    def research_portal(body: PortalBody, a: dict = Depends(agent)):
        return _research(wb.fetch_authenticated, a, body.url, body.credential, body.approval_id)

    @app.post("/v1/research/tor/fetch")
    def research_tor(body: FetchBody, a: dict = Depends(agent)):
        return _research(tr.fetch, a, body.url, body.mission_id)

    @app.get("/admin/research/evidence", dependencies=[Depends(admin)])
    def research_evidence(darkweb: bool = False):
        return (tr.evidence if darkweb else wb.evidence).list()

    @app.post("/admin/research/tor/setup", dependencies=[Depends(admin)])
    def research_tor_setup():
        return _research(tr.setup)

    @app.get("/admin/research/tor/status", dependencies=[Depends(admin)])
    def research_tor_status():
        try:
            return tr.status()
        except OSError as exc:
            return {"network_internal": False, "gateway_running": False, "error": str(exc)}

    # ----- security operations -----
    @app.get("/v1/secops/tools")
    def secops_tools(_: dict = Depends(agent)):
        return sec.tools()

    @app.post("/v1/secops/run")
    def secops_run(body: ToolRunBody, a: dict = Depends(agent)):
        try:
            return sec.run_tool(a, body.tool, target=body.target, engagement_id=body.engagement_id, folder=body.folder,
                                options=body.options, approval_id=body.approval_id)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        except SandboxUnavailable as exc:
            raise HTTPException(503, str(exc))

    @app.post("/v1/secops/findings/{fid}/verify")
    def secops_verify(fid: str, body: VerifyBody, a: dict = Depends(agent)):
        try:
            return sec.verify_finding(a, fid, body.approval_id)
        except KeyError as exc:
            raise HTTPException(404, str(exc))
        except SandboxUnavailable as exc:
            raise HTTPException(503, str(exc))

    @app.get("/admin/secops/findings", dependencies=[Depends(admin)])
    def secops_findings(engagement_id: Optional[str] = None, status: Optional[str] = None):
        return sec.findings(engagement_id, status)

    @app.put("/admin/secops/findings/{fid}", dependencies=[Depends(admin)])
    def secops_status(fid: str, body: StatusBody):
        try:
            return {"ok": sec.set_status(fid, body.status, "admin")}
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.get("/admin/secops/runs", dependencies=[Depends(admin)])
    def secops_runs(engagement_id: Optional[str] = None):
        return sec.runs(engagement_id)

    @app.get("/admin/secops/report/{engagement_id}", dependencies=[Depends(admin)])
    def secops_report(engagement_id: str):
        from fastapi.responses import PlainTextResponse
        try:
            return PlainTextResponse(sec.report(engagement_id), media_type="text/markdown")
        except KeyError as exc:
            raise HTTPException(404, str(exc))

    @app.post("/admin/secops/alerts/suricata", dependencies=[Depends(admin)])
    async def secops_suricata(request: Request):
        return {"ingested": sec.ingest_suricata((await request.body()).decode("utf-8", "replace"))}

    @app.get("/admin/secops/alerts", dependencies=[Depends(admin)])
    def secops_alerts():
        return sec.alerts()

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
        if queue_mode:
            mid = mis.create(body.goal, "admin")
            queue.enqueue("mission.run", {"mission_id": mid}, idem=f"mission:{mid}")
            return {"id": mid, "queued": True}
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
            if queue_mode:
                mis.resume(mid, background=None)
                queue.enqueue("mission.run", {"mission_id": mid}, idem=f"mission:{mid}:resume:{int(time.time())}")
            else:
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
        sk = skm.sandbox
        return {**ctl.status(),
                "sandbox": {**dict(zip(("available", "detail"), sbx.available())),
                            "skills": {**dict(zip(("available", "detail"), sk.available())),
                                       "isolation": getattr(sk, "isolation", "docker")}},
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

    from .chat_routes import mount as mount_chat
    app.state.chat_parts = mount_chat(app, admin, ctl, router, skills=skm, web=wb, engine=eng)

    @app.get("/", include_in_schema=False)
    def root():
        from fastapi.responses import RedirectResponse
        return RedirectResponse("/app")

    return app
