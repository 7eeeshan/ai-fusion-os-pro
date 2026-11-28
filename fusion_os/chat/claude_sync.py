"""Keep this app in step with what the person set up in Claude (desktop app and Claude Code).

Read only, from these places (nothing of Claude's is ever changed):
- MCP servers: claude_desktop_config.json (also the Microsoft Store copy) and ~/.claude.json;
- skills: ~/.claude/skills/<name>/SKILL.md;
- Claude Code plugins listed in ~/.claude/plugins/installed_plugins.json (only those enabled in
  ~/.claude/settings.json when it lists any): their skills/<name>/SKILL.md and their MCP servers (.mcp.json, or
  mcpServers in .claude-plugin/plugin.json, with ${CLAUDE_PLUGIN_ROOT} filled in).
New items are added, changed ones updated and removed ones removed here, on start and then about once a minute
when one of those files changed. Synced connectors start with every tool on Ask, like any connector, and keep the
permissions you give them. Items you added yourself are never touched. Connectors added on claude.ai (in your
Anthropic account) are not on this PC, so they can't be synced; add them here by URL.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Optional

from .connectors import check_remote_url, claude_config_files, read_claude_servers
from .instructions import parse_skill_md

SRC = "claude-sync:"


def _home(env: dict) -> Path:
    return Path(env.get("USERPROFILE") or env.get("HOME") or Path.home())


def _load(p: Path) -> dict:
    try:
        d = json.loads(p.read_text(encoding="utf-8-sig"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def installed_plugins(env: dict) -> list[dict]:
    """[{name, path}] of Claude Code plugins installed (and enabled, when settings say so)."""
    base = _home(env) / ".claude"
    data = _load(base / "plugins" / "installed_plugins.json")
    enabled = _load(base / "settings.json").get("enabledPlugins")
    found: dict[str, str] = {}

    def walk(key: str, v):
        if isinstance(v, dict):
            if isinstance(v.get("installPath"), str):
                found.setdefault(key, v["installPath"])
            for k, x in v.items():
                walk(k if "@" in k or key == "" else key, x)
        elif isinstance(v, list):
            for x in v:
                walk(key, x)
    walk("", data.get("plugins", data))
    out = []
    for name, path in found.items():
        if isinstance(enabled, dict) and name in enabled and not enabled[name]:
            continue
        p = Path(path)
        if p.is_dir():
            out.append({"name": name, "path": p})
    return sorted(out, key=lambda x: x["name"])


def _fill(v, root: str):
    if isinstance(v, str):
        return v.replace("${CLAUDE_PLUGIN_ROOT}", root)
    if isinstance(v, list):
        return [_fill(x, root) for x in v]
    if isinstance(v, dict):
        return {k: _fill(x, root) for k, x in v.items()}
    return v


def plugin_servers(plugin: dict) -> list[dict]:
    root = plugin["path"]
    servers: dict = {}
    mcp = _load(root / ".mcp.json")
    servers.update(mcp.get("mcpServers", mcp) if isinstance(mcp, dict) else {})
    manifest = _load(root / ".claude-plugin" / "plugin.json")
    ms = manifest.get("mcpServers")
    if isinstance(ms, str):
        ms = _load(root / ms)
        ms = ms.get("mcpServers", ms)
    if isinstance(ms, dict):
        servers.update(ms)
    out = []
    short = plugin["name"].split("@")[0]
    for name, s in servers.items():
        if not isinstance(s, dict):
            continue
        s = _fill(s, str(root))
        t = s.get("type") or ("stdio" if s.get("command") else "http")
        item = {"name": f"{short}: {name}", "file": str(root), "type": "stdio" if t == "stdio" else "http",
                "url": s.get("url", ""), "command": s.get("command", ""), "args": s.get("args") or [],
                "env": s.get("env") or {}, "headers": s.get("headers") or {}, "supported": True}
        if item["type"] == "http":
            try:
                check_remote_url(item["url"])
            except ValueError:
                item["supported"] = False
        out.append(item)
    return out


def skill_folders(env: dict) -> list[tuple[str, Path]]:
    """(origin, folder) for every Claude skill on this PC: personal ones and the ones plugins bring."""
    out = []
    personal = _home(env) / ".claude" / "skills"
    if personal.is_dir():
        out += [("skills", d) for d in sorted(personal.iterdir()) if (d / "SKILL.md").is_file()]
    for pl in installed_plugins(env):
        sk = pl["path"] / "skills"
        if sk.is_dir():
            out += [(pl["name"], d) for d in sorted(sk.iterdir()) if (d / "SKILL.md").is_file()]
    return out


def _folder_hash(d: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(d.rglob("*")):
        if p.is_file() and not p.is_symlink():
            h.update(p.relative_to(d).as_posix().encode())
            try:
                h.update(p.read_bytes())
            except OSError:
                pass
    return h.hexdigest()


def _server_key(s: dict) -> str:
    return hashlib.sha256(json.dumps([s["type"], s["url"], s["command"], s["args"], s["env"], s["headers"]],
                                     sort_keys=True).encode()).hexdigest()[:16]


class ClaudeSync:
    def __init__(self, conns, instr, state_file: Path, audit=None, env: Optional[dict] = None, connect: bool = True):
        self.conns, self.instr, self.audit, self.connect = conns, instr, audit, connect
        self.env = dict(os.environ if env is None else env)
        self.state_file = state_file
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._sig = ""

    # ---------- state ----------
    def state(self) -> dict:
        st = _load(self.state_file)
        st.setdefault("enabled", True)
        st.setdefault("connectors", {})  # claude key -> {id, hash}
        st.setdefault("skills", {})  # folder path -> {name, hash}
        return st

    def _save(self, st: dict) -> None:
        tmp = self.state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(st, indent=1), encoding="utf-8")
        tmp.replace(self.state_file)

    def set_enabled(self, on: bool) -> dict:
        st = self.state()
        st["enabled"] = bool(on)
        self._save(st)
        self._sig = ""
        return self.status()

    def status(self) -> dict:
        st = self.state()
        return {"enabled": st["enabled"], "last_run": st.get("last_run"), "last_changes": st.get("last_changes", []),
                "connectors": len(st["connectors"]), "skills": len(st["skills"]),
                "plugins": [p["name"] for p in installed_plugins(self.env)], "errors": st.get("errors", [])}

    # ---------- what to watch ----------
    def _signature(self) -> str:
        base = _home(self.env) / ".claude"
        files = list(claude_config_files(self.env)) + [base / "settings.json",
                                                       base / "plugins" / "installed_plugins.json"]
        parts = []
        for f in files:
            try:
                parts.append(f"{f}:{f.stat().st_mtime_ns}")
            except OSError:
                pass
        for root in [base / "skills"] + [p["path"] for p in installed_plugins(self.env)]:
            try:
                for d in root.rglob("*"):
                    if d.name in ("SKILL.md", ".mcp.json", "plugin.json"):
                        parts.append(f"{d}:{d.stat().st_mtime_ns}")
            except OSError:
                pass
        return hashlib.sha256("\n".join(sorted(parts)).encode()).hexdigest()

    # ---------- one pass ----------
    def run(self, force: bool = False) -> dict:
        with self._lock:
            st = self.state()
            if not st["enabled"]:
                return self.status()
            sig = self._signature()
            if sig == self._sig and not force:
                return self.status()
            changes, errors = [], []
            self._sync_connectors(st, changes, errors)
            self._sync_skills(st, changes, errors)
            st.update(last_run=time.time(), errors=errors[-20:])
            if changes:
                st["last_changes"] = (changes + st.get("last_changes", []))[:30]
            self._save(st)
            self._sig = sig
            if changes and self.audit:
                self.audit("claude.sync", {"changes": changes[:50]})
            return self.status()

    def _sync_connectors(self, st: dict, changes: list, errors: list) -> None:
        wanted: dict[str, dict] = {}
        for s in read_claude_servers(self.env):
            wanted[f"{Path(s['file']).name}/{s['name']}"] = s
        for pl in installed_plugins(self.env):
            for s in plugin_servers(pl):
                wanted[f"plugin:{pl['name']}/{s['name']}"] = s
        have = {c["id"]: c for c in self.conns.list()}
        kept: dict[str, tuple] = {}  # key -> (enabled, permissions) of a connector that changed in Claude
        # removed in Claude (or changed): remove here
        for key, rec in list(st["connectors"].items()):
            s = wanted.get(key)
            if s is not None and s["supported"] and _server_key(s) == rec["hash"] and rec["id"] in have:
                continue
            if rec["id"] in have:
                old = self.conns.get(rec["id"]) or {}
                if s is not None:
                    kept[key] = (old.get("enabled", True), old.get("permissions") or {})
                self.conns.remove(rec["id"])
                changes.append(f"{'removed' if s is None else 'updating'} connector {key.split('/', 1)[-1]}")
            del st["connectors"][key]
        # a connector you added yourself with the same command/URL is left alone, and not duplicated
        mine = {(c.get("url") or "", c.get("command") or "", tuple(c.get("args") or []))
                for c in self.conns.list() if not str(c.get("source", "")).startswith(SRC)}
        new: list[str] = []
        for key, s in wanted.items():
            if key in st["connectors"] or not s["supported"]:
                continue
            if (s["url"], s["command"], tuple(s["args"])) in mine:
                continue
            try:
                c = self.conns.add(s["name"], s["type"], s["url"], "", s["headers"], s["command"], s["args"], s["env"],
                                   source=SRC + key)
            except ValueError as exc:
                errors.append(f"{s['name']}: {exc}")
                continue
            if key in kept:
                self.conns.restore_settings(c["id"], *kept[key])
            st["connectors"][key] = {"id": c["id"], "hash": _server_key(s)}
            changes.append(f"{'updated' if key in kept else 'added'} connector {s['name']}")
            new.append(c["id"])
        if new and self.connect:  # read their tool lists one at a time, in the background
            threading.Thread(target=self._refresh, args=(new,), daemon=True, name="claude-sync-connect").start()

    def _refresh(self, ids: list) -> None:
        for cid in ids:
            try:
                self.conns.refresh(cid)
            except Exception:
                pass  # shown as "not connected" on the Connectors page

    def _sync_skills(self, st: dict, changes: list, errors: list) -> None:
        found = {str(d): (origin, d) for origin, d in skill_folders(self.env)}
        current = {s["name"]: s for s in self.instr.list()}
        for path, rec in list(st["skills"].items()):
            if path in found:
                continue
            s = current.get(rec["name"])
            if s and str(s.get("source", "")).startswith(SRC):
                self.instr.remove(rec["name"])
                changes.append(f"removed skill {rec['name']}")
            del st["skills"][path]
        claimed = {rec["name"]: path for path, rec in st["skills"].items()}
        for path, (origin, d) in found.items():
            h = _folder_hash(d)
            rec = st["skills"].get(path)
            if rec and rec["hash"] == h:
                continue
            try:
                meta, _ = parse_skill_md((d / "SKILL.md").read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            existing = current.get(rec["name"] if rec else "") or next(
                (s for s in current.values() if s["title"] == meta.get("name") or s["name"] == d.name), None)
            if existing and not str(existing.get("source", "")).startswith(SRC):
                continue  # you added this skill yourself: leave it
            if existing and claimed.get(existing["name"], path) != path:
                continue  # another Claude skill (e.g. a plugin's) already has this name: keep the first
            was_enabled = existing["enabled"] if existing else True
            try:
                s = self.instr.add_folder(d, source=SRC + origin)
            except (ValueError, OSError) as exc:
                errors.append(f"skill {d.name}: {exc}")
                continue
            if not was_enabled:
                self.instr.set_enabled(s["name"], False)
            st["skills"][path] = {"name": s["name"], "hash": h}
            claimed[s["name"]] = path
            changes.append(f"{'updated' if rec else 'added'} skill {s['name']}" +
                           (f" (from plugin {origin})" if origin != "skills" else ""))

    # ---------- background ----------
    def start(self, every_s: float = 60) -> None:
        def loop():
            while not self._stop.is_set():
                try:
                    self.run()
                except Exception as exc:  # never let syncing take the app down
                    st = self.state()
                    st["errors"] = (st.get("errors", []) + [f"sync failed: {exc}"])[-20:]
                    self._save(st)
                self._stop.wait(every_s)
        threading.Thread(target=loop, daemon=True, name="claude-sync").start()

    def stop(self) -> None:
        self._stop.set()
