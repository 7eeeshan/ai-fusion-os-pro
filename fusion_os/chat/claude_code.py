"""Open Claude Code on this PC with AI Fusion Engine Pro as its model, offline.

Claude Code (Anthropic's terminal coding agent) keeps its own plugins, skills, hooks and MCP servers in ~/.claude;
those all keep working, because only the model is swapped: the launched window gets ANTHROPIC_BASE_URL pointing at
the engine's Anthropic-compatible /v1/messages (with tool use), the engine token, and the local model. Nothing in
~/.claude is changed, so Claude Code started any other way still uses the person's Anthropic account.
Connectors added on claude.ai belong to the Anthropic account and need the internet; they are not available offline.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

CONTEXT = 32768  # Claude Code's system prompt and tools are ~10k tokens; 32k leaves room to work


def find_claude(env: Optional[dict] = None) -> Optional[str]:
    env = os.environ if env is None else env
    p = env.get("FUSION_OS_CLAUDE")
    if p:
        return p if Path(p).exists() else None
    found = shutil.which("claude")
    if found:
        return found
    if os.name == "nt":
        cands = []
        if env.get("USERPROFILE"):
            cands.append(Path(env["USERPROFILE"]) / ".local" / "bin" / "claude.exe")  # native installer
        if env.get("APPDATA"):
            cands.append(Path(env["APPDATA"]) / "npm" / "claude.cmd")
        for c in cands:
            if c.exists():
                return str(c)
    return None


def launch_env(base_env: dict, engine_url: str, token: str, model: str) -> dict:
    env = {k: v for k, v in base_env.items() if k not in ("ANTHROPIC_API_KEY", "CLAUDE_CODE_USE_BEDROCK",
                                                          "CLAUDE_CODE_USE_VERTEX", "CLAUDECODE")}
    env.update({
        "ANTHROPIC_BASE_URL": engine_url.rstrip("/"),
        "ANTHROPIC_AUTH_TOKEN": token,
        "ANTHROPIC_MODEL": model,
        "ANTHROPIC_DEFAULT_HAIKU_MODEL": model,
        "ANTHROPIC_DEFAULT_SONNET_MODEL": model,
        "ANTHROPIC_DEFAULT_OPUS_MODEL": model,
        "CLAUDE_CODE_MAX_CONTEXT_TOKENS": str(CONTEXT),
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",  # no telemetry, update checks or error reports
    })
    return env


def powershell_lines(engine_url: str, model: str) -> str:
    """For people who'd rather start it themselves (e.g. in VS Code's terminal). The token is read from the
    engine's config by AI Fusion; here it is left as a placeholder so it is not shown on screen."""
    return "\n".join([
        f'$env:ANTHROPIC_BASE_URL = "{engine_url.rstrip("/")}"',
        '$env:ANTHROPIC_AUTH_TOKEN = "<engine API token: Engine Pro > Connections>"',
        f'$env:ANTHROPIC_MODEL = "{model}"',
        f'$env:ANTHROPIC_DEFAULT_HAIKU_MODEL = "{model}"',
        f'$env:CLAUDE_CODE_MAX_CONTEXT_TOKENS = "{CONTEXT}"',
        '$env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1"',
        "claude"])


class ClaudeCodeLink:
    def __init__(self, engine, env: Optional[dict] = None):
        self.engine = engine  # EngineLink
        self.env = os.environ if env is None else env

    def model(self) -> Optional[str]:
        try:
            if not self.engine.status().get("connected"):
                return None
            ids = [m["id"] for m in self.engine.models() if m.get("id")]
        except Exception:
            return None
        want = self.env.get("FUSION_OS_ENGINE_MODEL")
        local = [i for i in ids if not i.startswith(("claude", "omniroute"))]
        if want and want in ids:
            return want
        return (local or ids or [None])[0]

    def status(self) -> dict:
        b = find_claude(self.env)
        m = self.model()
        out = {"installed": bool(b), "path": b, "engine": bool(m), "model": m, "context": CONTEXT,
               "engine_url": self.engine.base_url}
        if m:
            out["manual"] = powershell_lines(self.engine.base_url, m)
        return out

    def prepare_model(self, model: str) -> Optional[str]:
        """Ask the engine to (re)load the model with a context big enough for Claude Code. Returns a warning or None."""
        if "/" not in model:
            return None
        eid, name = model.split("/", 1)
        try:
            r = self.engine.client.post(f"{self.engine.base_url}/api/load", headers=self.engine._headers(),
                                        json={"engine": eid, "model": name, "ctx": CONTEXT}, timeout=900)
            if r.status_code >= 400:
                return f"the engine could not load {model} with a {CONTEXT}-token context: {r.text[:200]}"
        except Exception as exc:  # the engine may still serve it with its current context
            return f"could not ask the engine to load {model}: {exc}"[:300]
        return None

    def launch(self, folder: Path) -> dict:
        b = find_claude(self.env)
        if not b:
            raise RuntimeError("Claude Code is not installed on this PC")
        model = self.model()
        if not model:
            raise RuntimeError("AI Fusion Engine Pro is not running or has no model")
        self.engine._headers()  # looks the token up if it appeared later
        warning = self.prepare_model(model)
        env = launch_env(dict(self.env), self.engine.base_url, self.engine.token, model)
        if os.name == "nt":
            title = "Claude Code (offline, AI Fusion)"
            # cmd strips the outer quotes of a /k string that has more than two: "title ... & "C:\...\claude.exe""
            subprocess.Popen(f'cmd.exe /k "title {title} & "{b}""', cwd=str(folder), env=env,
                             creationflags=0x0000_0010)  # CREATE_NEW_CONSOLE: its own window
            return {"launched": True, "model": model, "folder": str(folder), "warning": warning}
        return {"launched": False, "model": model, "folder": str(folder), "warning": warning,
                "manual": powershell_lines(self.engine.base_url, model)}
