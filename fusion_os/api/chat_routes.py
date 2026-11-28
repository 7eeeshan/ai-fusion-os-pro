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
from ..sandbox import AutoSandbox


class NewChatBody(BaseModel):
    title: str = "New chat"


class ChatPatchBody(BaseModel):
    title: Optional[str] = Field(None, max_length=120)
    starred: Optional[bool] = None
    skill: Optional[str] = None
    project: Optional[str] = Field(None, max_length=1000)
    auto_edit: Optional[bool] = None
    auto_run: Optional[bool] = None
    opencode_commands: Optional[bool] = None


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
    bot = Assistant(ctl, agent, store, router, conns, instr, skills=skills, web=web, code=code, data_home=home,
                    workspace=workspace, opencode=oc)
    app.state.chat = bot

    def _chat(cid: str) -> dict:
        c = store.get(cid)
        if not c:
            raise HTTPException(404, "no such chat")
        return c

    @app.get("/app", include_in_schema=False)
    def chat_app():
        from importlib import resources as _r
        from fastapi.responses import HTMLResponse
        html = _r.files("fusion_os.api").joinpath("chat.html").read_text(encoding="utf-8")
        return HTMLResponse(html, headers={"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'; "
                                           "style-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'",
                                           "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"})

    # ----- chats -----
    @app.get("/admin/chat/chats", dependencies=[Depends(admin)])
    def chats(q: str = ""):
        return store.list(q)

    @app.post("/admin/chat/chats", dependencies=[Depends(admin)])
    def new_chat(body: NewChatBody):
        return store.create(body.title)

    @app.get("/admin/chat/chats/{cid}", dependencies=[Depends(admin)])
    def get_chat(cid: str):
        return {**_chat(cid), "messages": store.messages(cid), "project": bot.project(cid)}

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

    return {"store": store, "connectors": conns, "instructions": instr, "assistant": bot}
