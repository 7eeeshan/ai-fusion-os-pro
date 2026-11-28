"""Link to OpenCode (https://opencode.ai, MIT), the open source coding agent, installed on this PC.

The chat can hand a coding task to OpenCode with `opencode_task`. OpenCode then works in the chat's project folder
with its own tools. Guardrails:
- every hand-off is a `code.delegate` action: the person approves each one, seeing the task, the folder, the model and
  whether OpenCode may run commands;
- OpenCode runs with a config this app writes (OPENCODE_CONFIG): file edits allowed, shell commands denied unless the
  person turned them on for that chat, web fetches denied, nothing outside the project folder;
- when AI Fusion Engine Pro is running, OpenCode uses it as its model ("fusion" provider, local); otherwise it uses
  whatever model the person set up in OpenCode itself, and the card says so;
- the task is sent on stdin, never on the command line (Windows .cmd shims re-parse arguments);
- every file OpenCode changed is listed with a diff afterwards and written to the audit log.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

from ..paths import write_private
from .code import CodeTools

MAX_TRACK = 20_000
MAX_DIFF_FILE = 400_000


def find_opencode(env: Optional[dict] = None) -> Optional[str]:
    env = os.environ if env is None else env
    p = env.get("FUSION_OS_OPENCODE")
    if p:
        return p if Path(p).exists() else None
    found = shutil.which("opencode")
    if found:
        return found
    if os.name == "nt":  # npm's global folder is not always on PATH for apps started from the Start menu
        for base in (env.get("APPDATA"), env.get("LOCALAPPDATA")):
            if base:
                for c in (Path(base) / "npm" / "opencode.cmd", Path(base) / "Programs" / "opencode" / "opencode.exe"):
                    if c.exists():
                        return str(c)
    return None


class OpenCodeLink:
    def __init__(self, cfg_dir: Path, engine=None, env: Optional[dict] = None):
        self.cfg_dir = cfg_dir
        self.engine = engine  # EngineLink or None
        self.env = os.environ if env is None else env
        self._version: Optional[tuple[str, str]] = None

    def binary(self) -> Optional[str]:
        return find_opencode(self.env)

    def status(self) -> dict:
        b = self.binary()
        if not b:
            return {"installed": False}
        if not self._version or self._version[0] != b:
            try:
                out = subprocess.run([b, "--version"], capture_output=True, text=True, timeout=30,
                                     stdin=subprocess.DEVNULL, **_no_window())
                self._version = (b, (out.stdout or out.stderr).strip().splitlines()[-1][:40])
            except (OSError, subprocess.SubprocessError, IndexError):
                self._version = (b, "?")
        return {"installed": True, "path": b, "version": self._version[1]}

    # ---------- model ----------
    def engine_model(self) -> Optional[str]:
        """The Engine Pro model id to use, or None when the engine is not available."""
        if self.engine is None:
            return None
        try:
            if not self.engine.status().get("connected"):
                return None
            ids = [m["id"] for m in self.engine.models() if m.get("id")]
        except Exception:
            return None
        want = self.env.get("FUSION_OS_ENGINE_MODEL")
        if want and want in ids:
            return want
        return ids[0] if ids else None

    def write_config(self, root: Path, model: Optional[str], allow_commands: bool) -> Path:
        cfg: dict[str, Any] = {
            "$schema": "https://opencode.ai/config.json",
            "autoupdate": False,
            "share": "disabled",
            "permission": {"edit": "allow", "bash": "allow" if allow_commands else "deny", "webfetch": "deny",
                           "external_directory": "deny"},
        }
        if model and self.engine is not None:
            cfg["provider"] = {"fusion": {
                "npm": "@ai-sdk/openai-compatible", "name": "AI Fusion Engine Pro (local)",
                "options": {"baseURL": self.engine.base_url + "/v1", "apiKey": "{env:AFE_TOKEN}"},
                "models": {model: {"name": model}}}}
        path = self.cfg_dir / "opencode.json"
        self.cfg_dir.mkdir(parents=True, exist_ok=True)
        write_private(path, json.dumps(cfg, indent=2))
        return path

    # ---------- run ----------
    def run(self, root: Path, task: str, model: Optional[str], allow_commands: bool,
            session: Optional[str] = None, timeout_s: float = 900) -> dict:
        b = self.binary()
        if not b:
            raise RuntimeError("OpenCode is not installed")
        cfg = self.write_config(root, model, allow_commands)
        argv = [b, "run", "--format", "json", "--dir", str(root)]
        if model:
            argv += ["-m", f"fusion/{model}"]
        if session:
            argv += ["-s", session]
        env = dict(self.env)
        env["OPENCODE_CONFIG"] = str(cfg)
        if self.engine is not None and getattr(self.engine, "token", ""):
            self.engine._headers()  # looks the token up if it appeared later
            env["AFE_TOKEN"] = self.engine.token
        before = snapshot(root)
        t0 = time.monotonic()
        p = subprocess.Popen(argv, cwd=str(root), env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
                             **_no_window(new_group=True))
        timed_out = False
        try:
            out, err = p.communicate(task, timeout=timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_tree(p)
            out, err = p.communicate()
        changes = compare(root, before, snapshot(root))
        res = parse_events(out)
        res.update(exit_code=p.returncode, timed_out=timed_out, seconds=round(time.monotonic() - t0, 1),
                   stderr=(err or "")[-4000:], changes=changes)
        return res


def _no_window(new_group: bool = False) -> dict:
    if os.name != "nt":
        return {"start_new_session": True} if new_group else {}
    flags = 0x0800_0000  # CREATE_NO_WINDOW
    if new_group:
        flags |= 0x0000_0200  # CREATE_NEW_PROCESS_GROUP
    return {"creationflags": flags}


def _kill_tree(p: subprocess.Popen) -> None:
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"], capture_output=True, timeout=30,
                           **_no_window())
        else:
            os.killpg(p.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        p.kill()
    except OSError:
        pass


def parse_events(out: str) -> dict:
    """OpenCode's --format json prints one event per line; keep the text and a short list of tool uses."""
    texts, tools, session = [], [], None
    for line in (out or "").splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        session = ev.get("sessionID") or session
        part = ev.get("part") or {}
        if ev.get("type") == "text" and part.get("text"):
            texts.append(part["text"])
        elif ev.get("type") == "tool_use":
            st = part.get("state") or {}
            inp = st.get("input") or {}
            target = inp.get("filePath") or inp.get("command") or inp.get("pattern") or inp.get("url") or ""
            tools.append({"tool": part.get("tool"), "status": st.get("status"), "target": str(target)[:300]})
        elif ev.get("type") == "error":
            texts.append("[OpenCode error] " + json.dumps(ev.get("error") or ev)[:1000])
    return {"text": "\n\n".join(texts).strip(), "tools": tools, "session": session}


# ---------- what changed ----------
MAX_KEEP_TEXT = 30_000_000


def snapshot(root: Path) -> dict:
    """{path: (size, mtime, sha256, text or None)} for the project's files (text kept for diffs, within limits)."""
    snap: dict[str, tuple] = {}
    kept = 0
    walker = CodeTools.__new__(CodeTools)  # only the walker is needed
    for p in walker._walk(root, root):
        try:
            st = p.stat()
        except OSError:
            continue
        digest, text = "", None
        if st.st_size <= MAX_DIFF_FILE:
            try:
                data = p.read_bytes()
                digest = hashlib.sha256(data).hexdigest()
                if b"\x00" not in data[:8000] and kept + len(data) <= MAX_KEEP_TEXT:
                    text = data.decode("utf-8", errors="replace")
                    kept += len(data)
            except OSError:
                pass
        snap[p.relative_to(root).as_posix()] = (st.st_size, st.st_mtime, digest, text)
        if len(snap) >= MAX_TRACK:
            break
    return snap


def compare(root: Path, before: dict, after: dict) -> list[dict]:
    out = []
    for rel in sorted(set(before) | set(after)):
        a, b = before.get(rel), after.get(rel)
        if a and b and (a[2] == b[2] if a[2] and b[2] else a[:2] == b[:2]):
            continue
        kind = "added" if not a else "deleted" if not b else "changed"
        old = (a[3] if a else "") or ""
        new = (b[3] if b else "") or ""
        diff = CodeTools.diff(rel, old, new, kind == "added") if (a is None or a[3] is not None) and \
            (b is None or b[3] is not None) else "(binary or large file)"
        out.append({"path": rel, "change": kind, "diff": diff[:20000]})
    return out[:300]


def describe_changes(changes: list[dict]) -> str:
    if not changes:
        return "No files changed."
    head = "\n".join(f"{c['change']:>8}  {c['path']}" for c in changes)
    return head + "\n\n" + "\n\n".join(c["diff"] for c in changes if c.get("diff"))[:60000]
