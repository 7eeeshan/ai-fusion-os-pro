"""Connectors: MCP servers the chat can use, with a permission per tool.

- remote connectors (Streamable HTTP, https only) with an optional bearer token or headers;
- local connectors (a program on this PC speaking MCP over stdio), added by the person;
- import from the Claude desktop app's and Claude Code's MCP configuration (read only, nothing there is changed).

Each tool is "ask" (default: every call waits for the person's approval), "allow" or "off". Tools whose names
suggest payments, sending messages or deleting things can never be set to "allow": they always ask.
Connector settings, which can hold tokens, are kept in a private file in the data folder.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Optional

from .. import paths
from .mcp import HTTPSession, MCPError, StdioSession, check_remote_url

PERMISSIONS = ("ask", "allow", "off")
# Words in a tool name that mean money, messages to other people, or changes that are hard to undo.
STRONG = {"pay", "payment", "purchase", "buy", "checkout", "transfer", "refund", "charge", "send", "delete", "destroy",
          "wipe", "drop", "truncate", "publish", "tweet", "transaction", "order", "invoice", "wire"}
RISKY = STRONG | {"email", "mail", "message", "post", "reply", "comment", "invite", "share", "remove", "revoke",
                  "cancel", "deploy", "merge", "push", "execute", "exec", "run", "shell", "command", "write", "move",
                  "rename", "update", "create", "edit", "upload", "archive", "trash", "kill", "stop", "restart"}
SLUG = re.compile(r"[^a-z0-9_-]+")


def slug(name: str) -> str:
    s = SLUG.sub("-", name.lower()).strip("-")[:40]
    return s or "connector"


def _words(name: str) -> set[str]:
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return {w for w in re.split(r"[^a-zA-Z0-9]+", name.lower()) if w}


def is_risky(tool: dict) -> bool:
    """True if the tool may pay, send, publish or change things: it then always asks before each call."""
    ann = tool.get("annotations") or {}
    words = _words(tool.get("name", ""))
    if ann.get("destructiveHint") is True or words & STRONG:
        return True
    return bool(words & RISKY) and ann.get("readOnlyHint") is not True


class ConnectorManager:
    def __init__(self, path: Optional[Path] = None):
        self.path = path or (paths.home() / "connectors.json")
        self.lock = threading.RLock()
        self.sessions: dict[str, Any] = {}

    # ---------- storage ----------
    def _load(self) -> dict:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"connectors": {}}

    def _save(self, d: dict) -> None:
        tmp = self.path.with_suffix(".tmp")
        paths.write_private(tmp, json.dumps(d, indent=2))
        os.replace(tmp, self.path)

    def list(self) -> list[dict]:
        return [self._public(c) for c in self._load()["connectors"].values()]

    def get(self, cid: str) -> Optional[dict]:
        return self._load()["connectors"].get(cid)

    @staticmethod
    def _public(c: dict) -> dict:
        """What the interface sees: never the token or env values."""
        out = {k: c.get(k) for k in ("id", "name", "type", "url", "command", "args", "enabled", "last_error",
                                     "connected_at", "server", "source")}
        out["has_secret"] = bool(c.get("headers") or c.get("env"))
        out["env_keys"] = sorted((c.get("env") or {}).keys())
        perms = c.get("permissions", {})
        out["tools"] = [{"name": t["name"], "description": (t.get("description") or "")[:500],
                         "risky": is_risky(t), "permission": perms.get(t["name"], "ask")} for t in c.get("tools", [])]
        return out

    # ---------- add / change ----------
    def add(self, name: str, type_: str, url: str = "", token: str = "", headers: Optional[dict] = None,
            command: str = "", args: Optional[list[str]] = None, env: Optional[dict] = None,
            source: str = "manual") -> dict:
        if type_ not in ("http", "stdio"):
            raise ValueError("type must be http or stdio")
        h = {str(k): str(v) for k, v in (headers or {}).items()}
        if token:
            h["Authorization"] = "Bearer " + token.strip()
        c: dict = {"name": name.strip()[:60] or "Connector", "type": type_, "enabled": True, "tools": [],
                   "permissions": {}, "last_error": None, "source": source, "created": time.time()}
        if type_ == "http":
            c.update(url=check_remote_url(url.strip()), headers=h)
        else:
            if not command.strip():
                raise ValueError("a local connector needs a command")
            c.update(command=command.strip(), args=[str(a) for a in (args or [])],
                     env={str(k): str(v) for k, v in (env or {}).items()})
        with self.lock:
            d = self._load()
            base = cid = slug(c["name"])
            n = 2
            while cid in d["connectors"]:
                cid, n = f"{base}-{n}", n + 1
            c["id"] = cid
            d["connectors"][cid] = c
            self._save(d)
        return self._public(c)

    def remove(self, cid: str) -> bool:
        with self.lock:
            self._drop_session(cid)
            d = self._load()
            ok = d["connectors"].pop(cid, None) is not None
            self._save(d)
        return ok

    def set_enabled(self, cid: str, enabled: bool) -> dict:
        with self.lock:
            d = self._load()
            c = d["connectors"][cid]
            c["enabled"] = bool(enabled)
            self._save(d)
            if not enabled:
                self._drop_session(cid)
        return self._public(c)

    def set_permission(self, cid: str, tool: str, permission: str) -> dict:
        if permission not in PERMISSIONS:
            raise ValueError(f"permission must be one of {PERMISSIONS}")
        with self.lock:
            d = self._load()
            c = d["connectors"][cid]
            t = next((t for t in c.get("tools", []) if t["name"] == tool), None)
            if t is None:
                raise KeyError(tool)
            if permission == "allow" and is_risky(t):
                raise ValueError("this tool can pay, send, publish or delete; it always asks before each use")
            c.setdefault("permissions", {})[tool] = permission
            self._save(d)
        return self._public(c)

    # ---------- sessions ----------
    def _drop_session(self, cid: str) -> None:
        s = self.sessions.pop(cid, None)
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    def _session(self, c: dict):
        s = self.sessions.get(c["id"])
        if s is not None and not (isinstance(s, StdioSession) and s.p.poll() is not None):
            return s
        if c["type"] == "http":
            s = HTTPSession(c["url"], c.get("headers"))
        else:
            s = StdioSession(c["command"], c.get("args"), c.get("env"))
        try:
            s.initialize()
        except Exception:
            s.close()
            raise
        self.sessions[c["id"]] = s
        return s

    def refresh(self, cid: str) -> dict:
        """Connect and (re)read the tool list."""
        with self.lock:
            d = self._load()
            c = d["connectors"][cid]
            self._drop_session(cid)
            try:
                s = self._session(c)
                tools = s.list_tools()
                c["tools"] = [{"name": t["name"], "description": t.get("description", ""),
                               "inputSchema": t.get("inputSchema") or {"type": "object"},
                               "annotations": t.get("annotations") or {}} for t in tools if t.get("name")]
                c["server"] = s.server_info
                c["last_error"] = None
                c["connected_at"] = time.time()
            except (MCPError, OSError, ValueError) as exc:
                c["last_error"] = str(exc)[:500]
            self._save(d)
        return self._public(c)

    def call(self, cid: str, tool: str, arguments: dict) -> dict:
        c = self.get(cid)
        if not c or not c.get("enabled"):
            raise MCPError("connector is not enabled")
        with self.lock:
            s = self._session(c)
        try:
            return s.call_tool(tool, arguments)
        except MCPError:
            # one reconnect, in case the server restarted or dropped the session
            with self.lock:
                self._drop_session(cid)
                s = self._session(c)
            return s.call_tool(tool, arguments)

    def tools_for_chat(self) -> list[dict]:
        """Enabled tools as the chat offers them: id `connector__tool`, permission, schema."""
        out = []
        for c in self._load()["connectors"].values():
            if not c.get("enabled"):
                continue
            perms = c.get("permissions", {})
            for t in c.get("tools", []):
                p = perms.get(t["name"], "ask")
                if p == "off":
                    continue
                if p == "allow" and is_risky(t):
                    p = "ask"
                out.append({"id": f"{c['id']}__{t['name']}", "connector": c["id"], "connector_name": c["name"],
                            "tool": t["name"], "description": (t.get("description") or "")[:800],
                            "schema": t.get("inputSchema") or {}, "permission": p})
        return out

    def close_all(self) -> None:
        for cid in list(self.sessions):
            self._drop_session(cid)


# ---------- import from Claude ----------
def claude_config_files(env: Optional[dict] = None) -> list[Path]:
    env = os.environ if env is None else env
    home = Path(env.get("USERPROFILE") or env.get("HOME") or Path.home())
    out: list[Path] = []
    if env.get("APPDATA"):
        out.append(Path(env["APPDATA"]) / "Claude" / "claude_desktop_config.json")
    if env.get("LOCALAPPDATA"):
        pk = Path(env["LOCALAPPDATA"]) / "Packages"
        if pk.is_dir():
            out += sorted(p / "LocalCache" / "Roaming" / "Claude" / "claude_desktop_config.json"
                          for p in pk.glob("Claude_*"))
    out += [home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
            home / ".config" / "Claude" / "claude_desktop_config.json",
            home / ".claude.json"]
    seen, res = set(), []
    for p in out:
        if p.is_file() and str(p) not in seen:
            seen.add(str(p))
            res.append(p)
    return res


def read_claude_servers(env: Optional[dict] = None) -> list[dict]:
    """MCP servers configured for the Claude desktop app and Claude Code. The files are only read."""
    found = []
    for f in claude_config_files(env):
        try:
            data = json.loads(f.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            continue
        for name, s in (data.get("mcpServers") or {}).items():
            if not isinstance(s, dict):
                continue
            t = s.get("type") or ("stdio" if s.get("command") else "http")
            item = {"name": name, "file": str(f), "type": "stdio" if t == "stdio" else "http",
                    "url": s.get("url", ""), "command": s.get("command", ""), "args": s.get("args") or [],
                    "env": s.get("env") or {}, "headers": s.get("headers") or {}, "supported": True, "note": ""}
            if t == "sse":
                item["note"] = "uses the older SSE transport; it is tried as Streamable HTTP"
            if item["type"] == "http":
                try:
                    check_remote_url(item["url"])
                except ValueError as exc:
                    item.update(supported=False, note=str(exc))
            found.append(item)
    return found


def preview(item: dict) -> dict:
    """Import list entry for the interface: no secret values."""
    return {k: item[k] for k in ("name", "file", "type", "url", "command", "args", "supported", "note")} | {
        "env_keys": sorted(item["env"]), "header_keys": sorted(item["headers"])}
