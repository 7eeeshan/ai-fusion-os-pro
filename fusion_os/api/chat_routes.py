"""HTTP routes for the chat interface: chats, connectors (MCP) and instruction skills. All need the admin token,
which the desktop app gets through its launch secret."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

from .. import paths
from ..chat import (Assistant, ChatStore, ConnectorManager, InstructionSkills, claude_skill_folders, preview,
                    read_claude_servers)
from ..chat.code import CodeError, CodeTools, check_project
from ..chat.opencode import OpenCodeLink
from ..chat.claude_code import ClaudeCodeLink
from ..chat.claude_sync import ClaudeSync
from ..chat.computer import ComputerError, ComputerUse
from ..chat.spaces import SpaceError, Spaces
from ..chat.learning import LessonStore
from ..models.lora import LoraTrainer
from ..chat.self_ui import AppOverlay, UIChangeError
from ..sandbox import AutoSandbox


class NewChatBody(BaseModel):
    title: str = "New chat"
    space: Optional[str] = Field(None, max_length=40)


class SpaceBody(BaseModel):
    name: Optional[str] = Field(None, max_length=120)
    description: Optional[str] = Field(None, max_length=2000)
    instructions: Optional[str] = Field(None, max_length=40000)


class SpaceFileBody(BaseModel):
    name: str = Field(max_length=200)
    content: str = Field(max_length=2_100_000)


class RateBody(BaseModel):
    message_id: int
    rating: int = Field(..., ge=-1, le=1)
    note: str = Field("", max_length=4000)  # what was wrong / what to do instead: becomes a lesson
    better: str = Field("", max_length=20000)  # a better answer, written by the person: used for training


class SyncBody(BaseModel):
    enabled: bool


class LessonBody(BaseModel):
    text: Optional[str] = Field(None, max_length=400)
    enabled: Optional[bool] = None


class TrainBody(BaseModel):
    repo: Optional[str] = Field(None, pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    epochs: float = Field(2, gt=0, le=10)
    gpu_mem_gb: float = Field(0, ge=0, le=80)
    job: Optional[str] = Field(None, pattern=r"^job-[0-9-]+$")
    scale: float = Field(1.0, ge=0, le=2)


class UIVersionBody(BaseModel):
    page: str = Field(..., pattern=r"^(chat|dashboard)\.html$")
    version: Optional[int] = Field(None, ge=0)  # None = undo the last change


class LaunchBody(BaseModel):
    chat: Optional[str] = Field(None, max_length=64)  # open in that chat's project folder (default: the workspace)


class ChatPatchBody(BaseModel):
    title: Optional[str] = Field(None, max_length=120)
    starred: Optional[bool] = None
    skill: Optional[str] = None
    project: Optional[str] = Field(None, max_length=1000)
    auto_edit: Optional[bool] = None
    auto_run: Optional[bool] = None
    opencode_commands: Optional[bool] = None
    computer: Optional[bool] = None
    computer_auto: Optional[bool] = None
    space: Optional[str] = Field(None, max_length=40)  # "" = out of its project


class FileBody(BaseModel):
    name: str = Field(max_length=200)
    content: str = Field(max_length=400_000)


class SendBody(BaseModel):
    text: str = Field(max_length=100_000)
    links: list[str] = Field(default_factory=list, max_length=5)
    files: list[FileBody] = Field(default_factory=list, max_length=10)
    skill: Optional[str] = None


class ApproveBody(BaseModel):
    message_id: int
    approve: bool
    always: bool = False


class ConnectorBody(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    type: str = "http"
    url: str = ""
    token: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    command: str = ""
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)


class EnabledBody(BaseModel):
    enabled: bool


class PermissionBody(BaseModel):
    permission: str


class ImportBody(BaseModel):
    names: list[str]


class SkillAddBody(BaseModel):
    skill_md: Optional[str] = Field(None, max_length=2_000_000)
    zip_b64: Optional[str] = Field(None, max_length=30_000_000)


def mount(app: FastAPI, admin, ctl, router, skills=None, web=None, code_sandbox=None, engine=None) -> dict[str, Any]:
    store = ChatStore(paths.home() / "chats.db")
    conns = ConnectorManager(paths.home() / "connectors.json")
    instr = InstructionSkills(paths.home() / "instruction_skills")
    token = ctl.register_agent("desktop-chat", ["standard", "research"])
    agent = ctl.agent_for_token(token)
    home = paths.home()
    workspace = Path(os.environ.get("FUSION_OS_WORKSPACE") or home / "workspace")
    workspace.mkdir(parents=True, exist_ok=True)
    runs = home / "code_runs"
    # Code runs are model-written, so unlike the raw /v1/sandbox/exec route they may use the process sandbox only
    # because the person approves each run (or turned on auto-approve for that chat's project).
    sbx = code_sandbox or AutoSandbox(allowed_images=("python:3.12-slim",), workroot=runs, allow_process=True)
    code = CodeTools(sbx, runs)
    oc = OpenCodeLink(home / "opencode", engine=engine)
    cc = ClaudeCodeLink(engine) if engine is not None else None
    overlay = AppOverlay(home / "app_overlay")
    spaces = Spaces(home / "projects")
    lessons = LessonStore(home / "learning.db")
    app.state.lessons = lessons
    trainer = LoraTrainer(home, engine, lessons) if engine is not None else None
    app.state.overlay = overlay
    bot = Assistant(ctl, agent, store, router, conns, instr, skills=skills, web=web, code=code, data_home=home,
                    workspace=workspace, opencode=oc, overlay=overlay, lessons=lessons,
                    computer=ComputerUse(home / "computer_shots"), spaces=spaces)
    app.state.chat = bot
    sync = ClaudeSync(conns, instr, home / "claude_sync.json", audit=lambda e, d: ctl.audit.append("admin", e, d))
    app.state.claude_sync = sync
    if os.environ.get("FUSION_OS_CLAUDE_SYNC", "1") != "0":
        sync.start()

    def _chat(cid: str) -> dict:
        c = store.get(cid)
        if not c:
            raise HTTPException(404, "no such chat")
        return c

    @app.get("/app", include_in_schema=False)
    def chat_app(safe: int = 0):
        from fastapi.responses import HTMLResponse
        html = overlay.serve("chat.html", safe=bool(safe))
        return HTMLResponse(html, headers={"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'; "
                                           "style-src 'unsafe-inline'; img-src 'self' data: blob:; frame-ancestors 'none'",
                                           "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"})

    # ----- chats -----
    @app.get("/admin/chat/chats", dependencies=[Depends(admin)])
    def chats(q: str = "", space: str = ""):
        cs = store.list(q)
        return [c for c in cs if c["settings"].get("space") == space] if space else cs

    @app.post("/admin/chat/chats", dependencies=[Depends(admin)])
    def new_chat(body: NewChatBody):
        settings = None
        if body.space:
            try:
                spaces.get(body.space)
            except KeyError:
                raise HTTPException(404, "no such project")
            settings = {"space": body.space}
        return store.create(body.title, settings=settings)

    # ----- projects (instructions and knowledge shared by their chats) -----
    def _space(sid: str) -> dict:
        try:
            return spaces.get(sid)
        except KeyError:
            raise HTTPException(404, "no such project")

    @app.get("/admin/projects", dependencies=[Depends(admin)])
    def list_spaces():
        counts: dict[str, int] = {}
        for c in store.list(limit=5000):
            sid = c["settings"].get("space")
            if sid:
                counts[sid] = counts.get(sid, 0) + 1
        return [{**s, "chats": counts.get(s["id"], 0)} for s in spaces.list()]

    @app.post("/admin/projects", dependencies=[Depends(admin)])
    def create_space(body: SpaceBody):
        try:
            s = spaces.create(body.name or "", body.description or "", body.instructions or "")
        except SpaceError as exc:
            raise HTTPException(400, str(exc))
        _audit("project.create", {"id": s["id"]})
        return s

    @app.get("/admin/projects/{sid}", dependencies=[Depends(admin)])
    def get_space(sid: str):
        return {**_space(sid), "chat_list": [c for c in store.list(limit=5000) if c["settings"].get("space") == sid]}

    @app.patch("/admin/projects/{sid}", dependencies=[Depends(admin)])
    def update_space(sid: str, body: SpaceBody):
        _space(sid)
        try:
            return spaces.update(sid, body.name, body.description, body.instructions)
        except SpaceError as exc:
            raise HTTPException(400, str(exc))

    @app.delete("/admin/projects/{sid}", dependencies=[Depends(admin)])
    def delete_space(sid: str):
        _space(sid)
        for c in store.list(limit=5000):  # its chats stay, outside any project
            if c["settings"].get("space") == sid:
                store.update(c["id"], settings={k: v for k, v in c["settings"].items() if k != "space"})
        _audit("project.delete", {"id": sid})
        return {"ok": spaces.delete(sid)}

    @app.post("/admin/projects/{sid}/files", dependencies=[Depends(admin)])
    def add_space_file(sid: str, body: SpaceFileBody):
        _space(sid)
        try:
            out = spaces.add_file(sid, body.name, body.content)
        except SpaceError as exc:
            raise HTTPException(400, str(exc))
        _audit("project.file.add", {"id": sid, "file": out["name"], "size": out["size"]})
        return out

    @app.get("/admin/projects/{sid}/files/{name}", dependencies=[Depends(admin)])
    def read_space_file(sid: str, name: str):
        _space(sid)
        try:
            return {"name": name, "content": spaces.read_file(sid, name)}
        except KeyError:
            raise HTTPException(404, "no such file")

    @app.delete("/admin/projects/{sid}/files/{name}", dependencies=[Depends(admin)])
    def remove_space_file(sid: str, name: str):
        _space(sid)
        try:
            return {"ok": spaces.remove_file(sid, name)}
        except KeyError:
            raise HTTPException(404, "no such file")

    @app.get("/admin/chat/chats/{cid}", dependencies=[Depends(admin)])
    def get_chat(cid: str):
        sp = bot.space(cid)
        return {**_chat(cid), "messages": store.messages(cid), "project": bot.project(cid),
                "computer": bot.computer_settings(cid), "space": {"id": sp["id"], "name": sp["name"]} if sp else None}

    @app.patch("/admin/chat/chats/{cid}", dependencies=[Depends(admin)])
    def patch_chat(cid: str, body: ChatPatchBody):
        c = _chat(cid)
        settings = c["settings"]
        if body.skill is not None:
            settings = {**settings, "skill": body.skill or None}
        if body.project is not None:
            folder = body.project.strip()
            if folder:
                try:
                    folder = str(check_project(folder, home, workspace))
                except CodeError as exc:
                    raise HTTPException(400, str(exc))
            if folder != (settings.get("project") or ""):
                # auto-approve is given for one folder; a new folder starts with approvals on again
                settings = {**settings, "project": folder or None, "auto_edit": False, "auto_run": False,
                            "opencode_commands": False, "opencode_session": None}
        if body.space is not None:
            if body.space:
                _space(body.space)
                settings = {**settings, "space": body.space}
            else:
                settings = {k: v for k, v in settings.items() if k != "space"}
        if body.computer is False:
            settings = {**settings, "computer_auto": False}  # turning it back on starts with approvals again
        for k in ("computer", "computer_auto"):
            v = getattr(body, k)
            if v is not None and (k == "computer" or v is False or settings.get("computer")):
                settings = {**settings, k: v}
                ctl.audit.append("admin", f"chat.{k}", {"chat_id": cid, "on": v})
        for k in ("auto_edit", "auto_run", "opencode_commands"):
            v = getattr(body, k)
            if v is not None:
                settings = {**settings, k: v}
                ctl.audit.append("admin", f"chat.{k}", {"chat_id": cid, "on": v,
                                                         "project": settings.get("project") or str(workspace)})
        return store.update(cid, title=body.title, starred=body.starred, settings=settings)

    @app.delete("/admin/chat/chats/{cid}", dependencies=[Depends(admin)])
    def delete_chat(cid: str):
        return {"ok": store.delete(cid)}

    @app.post("/admin/chat/chats/{cid}/send", dependencies=[Depends(admin)])
    def send(cid: str, body: SendBody):
        _chat(cid)
        if not body.text.strip() and not body.links and not body.files:
            raise HTTPException(400, "empty message")
        return {"messages": bot.send(cid, body.text, body.links, [f.model_dump() for f in body.files], body.skill)}

    @app.post("/admin/chat/chats/{cid}/approve", dependencies=[Depends(admin)])
    def approve(cid: str, body: ApproveBody):
        _chat(cid)
        try:
            return {"messages": bot.resume(cid, body.message_id, body.approve, body.always)}
        except KeyError as exc:
            raise HTTPException(409, str(exc))

    @app.post("/admin/chat/chats/{cid}/retry", dependencies=[Depends(admin)])
    def retry(cid: str):
        _chat(cid)
        msgs = store.messages(cid)
        last_user = next((m for m in reversed(msgs) if m["role"] == "user"), None)
        if not last_user:
            raise HTTPException(400, "nothing to retry")
        store.truncate_after(cid, last_user["id"])
        return {"messages": bot._loop(cid)}

    @app.get("/admin/chat/tools", dependencies=[Depends(admin)])
    def chat_tools(chat: str = ""):
        return bot.tools(chat or None)

    @app.get("/admin/chat/opencode", dependencies=[Depends(admin)])
    def opencode_status():
        return {**oc.status(), "engine_model": oc.engine_model()}

    # ----- learning from feedback -----
    @app.post("/admin/chat/chats/{cid}/rate", dependencies=[Depends(admin)])
    def rate(cid: str, body: RateBody):
        _chat(cid)
        try:
            return bot.rate(cid, body.message_id, body.rating, body.note, body.better)
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.get("/admin/learning", dependencies=[Depends(admin)])
    def learning():
        return {"stats": lessons.stats(), "lessons": lessons.lessons(), "interface": overlay.history()}

    @app.post("/admin/learning/lessons", dependencies=[Depends(admin)])
    def add_lesson(body: LessonBody):
        try:
            out = lessons.add_lesson(body.text or "")
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        ctl.audit.append("admin", "learning.lesson.add", {"id": out["id"]})
        return out

    @app.patch("/admin/learning/lessons/{lid}", dependencies=[Depends(admin)])
    def edit_lesson(lid: int, body: LessonBody):
        lessons.update_lesson(lid, body.text, body.enabled)
        ctl.audit.append("admin", "learning.lesson.edit", {"id": lid, "enabled": body.enabled})
        return {"ok": True}

    @app.delete("/admin/learning/lessons/{lid}", dependencies=[Depends(admin)])
    def delete_lesson(lid: int):
        lessons.delete_lesson(lid)
        ctl.audit.append("admin", "learning.lesson.delete", {"id": lid})
        return {"ok": True}

    # ----- LoRA training of the local model (each step started by the person) -----
    def _trainer() -> LoraTrainer:
        if trainer is None:
            raise HTTPException(409, "AI Fusion Engine Pro is not linked")
        return trainer

    def _step(event: str, fn, data: dict):
        try:
            out = fn()
        except RuntimeError as exc:
            raise HTTPException(409, str(exc))
        ctl.audit.append("admin", event, data)
        return out

    @app.get("/admin/learning/train", dependencies=[Depends(admin)])
    def train_status():
        return _trainer().status()

    @app.post("/admin/learning/train/runtime", dependencies=[Depends(admin)])
    def train_runtime():
        t = _trainer()
        return _step("model.install", t.setup_runtime, {"what": "lora trainer runtime"})

    @app.post("/admin/learning/train/base", dependencies=[Depends(admin)])
    def train_base(body: TrainBody):
        t = _trainer()
        return _step("model.install", lambda: t.download_base(body.repo), {"what": "base weights", "repo": body.repo})

    @app.post("/admin/learning/train/start", dependencies=[Depends(admin)])
    def train_start(body: TrainBody):
        t = _trainer()
        return _step("model.train", lambda: t.train(body.epochs, body.gpu_mem_gb), {"epochs": body.epochs})

    @app.post("/admin/learning/train/deploy", dependencies=[Depends(admin)])
    def train_deploy(body: TrainBody):
        t = _trainer()
        return _step("model.adapter.deploy", lambda: t.deploy(body.job or "", body.scale), {"job": body.job})

    @app.post("/admin/learning/train/rollback", dependencies=[Depends(admin)])
    def train_rollback():
        t = _trainer()
        return _step("model.adapter.rollback", t.rollback, {})

    # ----- the app's own interface (versions the assistant made, with approval) -----
    @app.get("/admin/app/ui", dependencies=[Depends(admin)])
    def app_ui():
        return overlay.history()

    @app.post("/admin/app/ui/activate", dependencies=[Depends(admin)])
    def app_ui_activate(body: UIVersionBody):
        try:
            v = overlay.undo(body.page) if body.version is None else overlay.activate(body.page, body.version)
        except (UIChangeError, KeyError) as exc:
            raise HTTPException(400, str(exc))
        ctl.audit.append("admin", "app.ui.activate", {"page": body.page, "version": v})
        return {"page": body.page, "active": v}

    @app.get("/admin/claude-code", dependencies=[Depends(admin)])
    def claude_code_status():
        return cc.status() if cc else {"installed": False, "engine": False}

    @app.post("/admin/claude-code/launch", dependencies=[Depends(admin)])
    def claude_code_launch(body: LaunchBody):
        if not cc:
            raise HTTPException(409, "AI Fusion Engine Pro is not linked")
        proj = bot.project(body.chat) if body.chat else None
        folder = proj["folder"] if proj and proj.get("root") else str(workspace)
        try:
            root = check_project(folder, home, workspace)
            out = cc.launch(root)
        except (CodeError, RuntimeError, OSError) as exc:
            raise HTTPException(409, str(exc))
        ctl.audit.append("admin", "claude_code.launch", {"folder": out["folder"], "model": out["model"],
                                                        "launched": out["launched"]})
        return out

    @app.get("/admin/chat/model", dependencies=[Depends(admin)])
    def chat_model():
        return {"providers": [getattr(p, "name", "?") for p in getattr(router, "providers", [])],
                "last": getattr(router, "last", {})}

    # ----- connectors -----
    def _audit(event: str, data: dict) -> None:
        ctl.audit.append("admin", event, data)

    @app.get("/admin/connectors", dependencies=[Depends(admin)])
    def connectors():
        return conns.list()

    @app.post("/admin/connectors", dependencies=[Depends(admin)])
    def add_connector(body: ConnectorBody):
        try:
            c = conns.add(body.name, body.type, body.url, body.token, body.headers, body.command, body.args, body.env)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        _audit("connector.add", {"id": c["id"], "type": c["type"], "url": c.get("url"), "command": c.get("command")})
        return conns.refresh(c["id"])

    @app.post("/admin/connectors/{cid}/refresh", dependencies=[Depends(admin)])
    def refresh_connector(cid: str):
        if not conns.get(cid):
            raise HTTPException(404, "no such connector")
        return conns.refresh(cid)

    @app.put("/admin/connectors/{cid}/enabled", dependencies=[Depends(admin)])
    def enable_connector(cid: str, body: EnabledBody):
        if not conns.get(cid):
            raise HTTPException(404, "no such connector")
        _audit("connector.enabled", {"id": cid, "enabled": body.enabled})
        return conns.set_enabled(cid, body.enabled)

    @app.put("/admin/connectors/{cid}/tools/{tool}", dependencies=[Depends(admin)])
    def tool_permission(cid: str, tool: str, body: PermissionBody):
        if not conns.get(cid):
            raise HTTPException(404, "no such connector")
        try:
            out = conns.set_permission(cid, tool, body.permission)
        except KeyError:
            raise HTTPException(404, "no such tool")
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        _audit("connector.permission", {"id": cid, "tool": tool, "permission": body.permission})
        return out

    @app.delete("/admin/connectors/{cid}", dependencies=[Depends(admin)])
    def remove_connector(cid: str):
        _audit("connector.remove", {"id": cid})
        return {"ok": conns.remove(cid)}

    @app.get("/admin/connectors/import/claude", dependencies=[Depends(admin)])
    def claude_connectors():
        existing = {(c.get("url") or "", c.get("command") or "", tuple(c.get("args") or [])) for c in conns.list()}
        out = []
        for s in read_claude_servers():
            p = preview(s)
            p["already_added"] = (s["url"], s["command"], tuple(s["args"])) in existing
            out.append(p)
        return out

    @app.post("/admin/connectors/import/claude", dependencies=[Depends(admin)])
    def import_claude_connectors(body: ImportBody):
        added, errors = [], []
        for s in read_claude_servers():
            if s["name"] not in body.names or not s["supported"]:
                continue
            try:
                c = conns.add(s["name"], s["type"], s["url"], "", s["headers"], s["command"], s["args"], s["env"],
                              source="claude:" + Path(s["file"]).name)
                _audit("connector.import", {"id": c["id"], "from": s["file"]})
                added.append(conns.refresh(c["id"]))
            except ValueError as exc:
                errors.append(f"{s['name']}: {exc}")
        return {"added": added, "errors": errors}

    # ----- computer use: screenshots shown in the chat -----
    @app.get("/admin/computer/shot/{name}", dependencies=[Depends(admin)])
    def computer_shot(name: str):
        from fastapi.responses import FileResponse
        try:
            f = bot.computer.shot_path(name)
        except ComputerError:
            raise HTTPException(400, "bad name")
        if not f.is_file():
            raise HTTPException(404, "screenshot no longer kept")
        return FileResponse(f, media_type="image/jpeg", headers={"Cache-Control": "private, max-age=3600"})

    # ----- keeping in step with Claude (desktop app and Claude Code) -----
    @app.get("/admin/claude-sync", dependencies=[Depends(admin)])
    def claude_sync_status():
        return sync.status()

    @app.post("/admin/claude-sync", dependencies=[Depends(admin)])
    def claude_sync_set(body: SyncBody):
        _audit("claude.sync.enabled", {"on": body.enabled})
        out = sync.set_enabled(body.enabled)
        return sync.run(force=True) if body.enabled else out

    @app.post("/admin/claude-sync/run", dependencies=[Depends(admin)])
    def claude_sync_run():
        return sync.run(force=True)

    # ----- instruction skills -----
    @app.get("/admin/iskills", dependencies=[Depends(admin)])
    def iskills():
        return instr.list()

    @app.get("/admin/iskills/{name}", dependencies=[Depends(admin)])
    def iskill(name: str):
        try:
            return {"name": name, "content": instr.read(name)}
        except KeyError:
            raise HTTPException(404, "no such skill")

    @app.post("/admin/iskills", dependencies=[Depends(admin)])
    def add_iskill(body: SkillAddBody):
        try:
            if body.zip_b64:
                s = instr.add_zip(body.zip_b64)
            elif body.skill_md:
                s = instr.add_text(body.skill_md)
            else:
                raise ValueError("send skill_md or zip_b64")
        except (ValueError, OSError) as exc:
            raise HTTPException(400, str(exc)[:500])
        except Exception as exc:  # bad zip
            raise HTTPException(400, f"could not read the skill: {str(exc)[:300]}")
        _audit("iskill.add", {"name": s["name"], "warnings": len(s["warnings"])})
        return s

    @app.put("/admin/iskills/{name}/enabled", dependencies=[Depends(admin)])
    def enable_iskill(name: str, body: EnabledBody):
        try:
            instr.set_enabled(name, body.enabled)
        except KeyError:
            raise HTTPException(404, "no such skill")
        return {"ok": True}

    @app.delete("/admin/iskills/{name}", dependencies=[Depends(admin)])
    def remove_iskill(name: str):
        _audit("iskill.remove", {"name": name})
        return {"ok": instr.remove(name)}

    @app.get("/admin/iskills/import/claude", dependencies=[Depends(admin)])
    def claude_skills():
        have = {s["name"] for s in instr.list()}
        out = []
        for d in claude_skill_folders():
            from ..chat.instructions import parse_skill_md
            meta, _ = parse_skill_md((d / "SKILL.md").read_text(encoding="utf-8", errors="replace"))
            out.append({"folder": d.name, "name": meta.get("name", d.name), "description": meta.get("description", ""),
                        "path": str(d), "already_added": d.name in have or meta.get("name") in have})
        return out

    @app.post("/admin/iskills/import/claude", dependencies=[Depends(admin)])
    def import_claude_skills(body: ImportBody):
        added, errors = [], []
        for d in claude_skill_folders():
            if d.name not in body.names:
                continue
            try:
                added.append(instr.add_folder(d, source="claude:" + d.name))
            except (ValueError, OSError) as exc:
                errors.append(f"{d.name}: {exc}")
        return {"added": added, "errors": errors}

    return {"store": store, "connectors": conns, "instructions": instr, "assistant": bot, "claude_sync": sync}
