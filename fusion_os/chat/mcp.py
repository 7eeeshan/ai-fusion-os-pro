"""Minimal Model Context Protocol client: the tools part of MCP over Streamable HTTP and over stdio.

Only what the chat needs: initialize, tools/list (with pagination) and tools/call. Remote servers must use https,
except on the loopback interface. Local (stdio) servers are programs on this PC that the person added themselves;
they run with a reduced environment but outside the sandbox, which is why adding one is an admin action.
"""
from __future__ import annotations

import ipaddress
import json
import os
import queue
import shutil
import subprocess
import threading
from typing import Any, Optional
from urllib.parse import urlsplit

import httpx

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "ai-fusion-os-pro", "version": "0.9.0"}
# Environment a local server inherits; everything else (tokens, keys) must be given explicitly in its config.
PASS_ENV = ("PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "TEMP", "TMP", "TMPDIR", "HOME",
            "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMFILES", "PROGRAMDATA", "LANG", "NUMBER_OF_PROCESSORS",
            "PROCESSOR_ARCHITECTURE", "OS", "HOMEDRIVE", "HOMEPATH", "USERNAME")


class MCPError(RuntimeError):
    pass


def check_remote_url(url: str) -> str:
    p = urlsplit(url)
    if p.scheme not in ("https", "http") or not p.hostname:
        raise ValueError("connector URL must be http(s) with a host")
    if p.scheme == "http":
        host = p.hostname
        try:
            loop = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loop = host == "localhost"
        if not loop:
            raise ValueError("remote connectors must use https (plain http is only allowed on this PC)")
    return url


class _Session:
    def __init__(self):
        self._id = 0
        self.server_info: dict = {}
        self.instructions = ""

    def next_id(self) -> int:
        self._id += 1
        return self._id

    def request(self, method: str, params: Optional[dict] = None, timeout: float = 60) -> Any:
        raise NotImplementedError

    def notify(self, method: str, params: Optional[dict] = None) -> None:
        raise NotImplementedError

    def close(self) -> None:
        pass

    # ---------- protocol ----------
    def initialize(self) -> dict:
        res = self.request("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                                          "clientInfo": CLIENT_INFO}, timeout=60)
        self.server_info = res.get("serverInfo", {}) if isinstance(res, dict) else {}
        self.instructions = (res or {}).get("instructions", "") or ""
        self.notify("notifications/initialized")
        return res

    def list_tools(self) -> list[dict]:
        tools, cursor = [], None
        for _ in range(20):
            res = self.request("tools/list", {"cursor": cursor} if cursor else {})
            tools += res.get("tools", [])
            cursor = res.get("nextCursor")
            if not cursor:
                break
        return tools

    def call_tool(self, name: str, arguments: dict, timeout: float = 120) -> dict:
        return self.request("tools/call", {"name": name, "arguments": arguments}, timeout=timeout)


def _result(msg: dict) -> Any:
    if "error" in msg:
        e = msg["error"] or {}
        raise MCPError(f"{e.get('code')}: {str(e.get('message'))[:300]}")
    return msg.get("result", {})


class HTTPSession(_Session):
    def __init__(self, url: str, headers: Optional[dict] = None, client: Optional[httpx.Client] = None):
        super().__init__()
        self.url = check_remote_url(url)
        self.headers = dict(headers or {})
        self.client = client or httpx.Client(timeout=120, follow_redirects=False)
        self.session_id: Optional[str] = None
        self.version: Optional[str] = None

    def _hdrs(self) -> dict:
        h = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json", **self.headers}
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        if self.version:
            h["MCP-Protocol-Version"] = self.version
        return h

    def _post(self, body: dict, timeout: float) -> Optional[dict]:
        try:
            with self.client.stream("POST", self.url, json=body, headers=self._hdrs(), timeout=timeout) as r:
                if r.status_code in (401, 403):
                    raise MCPError(f"the server refused the credentials (HTTP {r.status_code})")
                if r.status_code == 202:
                    return None
                if r.status_code >= 400:
                    r.read()
                    raise MCPError(f"HTTP {r.status_code}: {r.text[:300]}")
                sid = r.headers.get("mcp-session-id")
                if sid:
                    self.session_id = sid
                ctype = r.headers.get("content-type", "")
                if "text/event-stream" in ctype:
                    return self._from_sse(r, body.get("id"))
                r.read()
                if not r.content:
                    return None
                data = r.json()
        except httpx.HTTPError as exc:
            raise MCPError(f"could not reach the connector: {str(exc)[:200]}") from exc
        if isinstance(data, list):
            data = next((m for m in data if m.get("id") == body.get("id")), {})
        return data

    @staticmethod
    def _from_sse(r: httpx.Response, want_id: Any) -> Optional[dict]:
        buf: list[str] = []
        size = 0
        for line in r.iter_lines():
            size += len(line)
            if size > 20_000_000:
                raise MCPError("connector response too large")
            if line.startswith("data:"):
                buf.append(line[5:].lstrip())
            elif line == "" and buf:
                try:
                    msg = json.loads("\n".join(buf))
                except ValueError:
                    msg = None
                buf = []
                if isinstance(msg, dict) and msg.get("id") == want_id and ("result" in msg or "error" in msg):
                    return msg
        if buf:
            msg = json.loads("\n".join(buf))
            if msg.get("id") == want_id:
                return msg
        raise MCPError("connector closed the stream without answering")

    def request(self, method: str, params: Optional[dict] = None, timeout: float = 60) -> Any:
        body = {"jsonrpc": "2.0", "id": self.next_id(), "method": method, "params": params or {}}
        msg = self._post(body, timeout)
        if msg is None:
            raise MCPError(f"no answer to {method}")
        res = _result(msg)
        if method == "initialize":
            self.version = (res or {}).get("protocolVersion") or PROTOCOL_VERSION
        return res

    def notify(self, method: str, params: Optional[dict] = None) -> None:
        try:
            self._post({"jsonrpc": "2.0", "method": method, "params": params or {}}, 30)
        except MCPError:
            pass

    def close(self) -> None:
        if self.session_id:
            try:
                self.client.delete(self.url, headers=self._hdrs(), timeout=5)
            except httpx.HTTPError:
                pass


class StdioSession(_Session):
    def __init__(self, command: str, args: Optional[list[str]] = None, env: Optional[dict] = None,
                 cwd: Optional[str] = None):
        super().__init__()
        exe = shutil.which(command) or command
        base = {k: v for k, v in os.environ.items() if k.upper() in PASS_ENV}
        base.update({k: str(v) for k, v in (env or {}).items()})
        kw: dict = {}
        if os.name == "nt":
            kw["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
        else:
            kw["start_new_session"] = True
        try:
            self.p = subprocess.Popen([exe, *(args or [])], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, env=base, cwd=cwd, **kw)
        except OSError as exc:
            raise MCPError(f"could not start {command!r}: {exc}") from exc
        self.lock = threading.Lock()
        self.inbox: "queue.Queue[dict]" = queue.Queue()
        self.stderr_tail: list[str] = []
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self._read_err, daemon=True).start()

    def _read(self) -> None:
        for raw in self.p.stdout:  # type: ignore[union-attr]
            try:
                msg = json.loads(raw.decode("utf-8", "replace"))
            except ValueError:
                continue
            if isinstance(msg, dict):
                self.inbox.put(msg)
        self.inbox.put({"_eof": True})

    def _read_err(self) -> None:
        for raw in self.p.stderr:  # type: ignore[union-attr]
            self.stderr_tail = (self.stderr_tail + [raw.decode("utf-8", "replace").rstrip()])[-20:]

    def _send(self, body: dict) -> None:
        try:
            self.p.stdin.write((json.dumps(body) + "\n").encode("utf-8"))  # type: ignore[union-attr]
            self.p.stdin.flush()  # type: ignore[union-attr]
        except OSError as exc:
            raise MCPError(f"local connector stopped: {exc}; {' | '.join(self.stderr_tail[-3:])}") from exc

    def request(self, method: str, params: Optional[dict] = None, timeout: float = 60) -> Any:
        with self.lock:
            rid = self.next_id()
            self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
            while True:
                try:
                    msg = self.inbox.get(timeout=timeout)
                except queue.Empty:
                    raise MCPError(f"local connector did not answer {method} in {timeout:.0f}s")
                if msg.get("_eof"):
                    raise MCPError("local connector exited: " + " | ".join(self.stderr_tail[-3:]))
                if msg.get("id") == rid and ("result" in msg or "error" in msg):
                    return _result(msg)
                if "method" in msg and "id" in msg:  # server->client request (sampling, roots...): not supported
                    self._send({"jsonrpc": "2.0", "id": msg["id"],
                                "error": {"code": -32601, "message": "not supported by this client"}})

    def notify(self, method: str, params: Optional[dict] = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def close(self) -> None:
        try:
            self.p.stdin.close()  # type: ignore[union-attr]
            self.p.wait(3)
        except (OSError, subprocess.TimeoutExpired):
            self.p.kill()


def tool_text(result: dict) -> str:
    """Flatten a tools/call result into text for the model."""
    parts = []
    for c in result.get("content", []) or []:
        t = c.get("type")
        if t == "text":
            parts.append(c.get("text", ""))
        elif t == "resource":
            r = c.get("resource", {})
            parts.append(r.get("text") or f"[resource {r.get('uri')}]")
        elif t == "resource_link":
            parts.append(f"[link {c.get('name') or ''} {c.get('uri')}]")
        else:
            parts.append(f"[{t} content omitted]")
    if not parts and result.get("structuredContent") is not None:
        parts.append(json.dumps(result["structuredContent"])[:50_000])
    return "\n".join(parts)
