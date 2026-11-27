"""Skill manager: submit -> validate -> approve -> active, with versions and rollback.

A skill is a small folder with `skill.json`, an entrypoint script, and tests. Validation is real and automatic:
manifest and licence checks, a file and size check, static analysis of the code (AST), dependency check, then the
skill's own tests and an example run inside the Docker sandbox with no network. Only validated skills can be
registered, and registration goes through the security controller, which requires a human approval. Approved
skills run for any agent allowed `skill.execute`, always inside the sandbox.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import stat
import time
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

from ..sandbox import DockerSandbox, SandboxSpec, SandboxUnavailable, make_sandbox
from ..security.controller import SecurityController, Verdict
from ..security.policy import ActionRequest

LICENSE_ALLOWLIST = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0", "PSF-2.0", "Unlicense", "0BSD"}
ALLOWED_SUFFIXES = {".py", ".json", ".md", ".txt", ".csv"}
MAX_TOTAL_BYTES = 1_000_000
IMAGE = "python:3.12-slim"
FORBIDDEN_MODULES = {"subprocess", "ctypes", "socket", "pickle", "marshal", "multiprocessing", "pty", "shutil",
                     "importlib", "urllib", "http", "ftplib", "smtplib", "telnetlib", "ssl", "winreg", "_winapi"}
NETWORK_MODULES = {"socket", "urllib", "http", "ssl"}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__", "breakpoint"}
FORBIDDEN_ATTRS = {"system", "popen", "spawnl", "spawnv", "execv", "execl", "fork", "kill", "remove", "rmdir",
                   "unlink", "chmod", "chown", "putenv", "startfile"}


class SkillManifest(BaseModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9-]{1,48}$")
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    description: str = Field(min_length=5, max_length=500)
    entrypoint: str = "main.py"
    license: str
    author: str = "unknown"
    network: str = "none"
    timeout_s: float = Field(30, ge=1, le=600)
    example_input: dict[str, Any] = Field(default_factory=dict)
    capabilities: list[str] = Field(default_factory=list)  # free-text tags used for capability-gap matching

    @field_validator("license")
    @classmethod
    def _lic(cls, v: str) -> str:
        if v not in LICENSE_ALLOWLIST:
            raise ValueError(f"licence {v!r} is not on the allowlist {sorted(LICENSE_ALLOWLIST)}")
        return v

    @field_validator("network")
    @classmethod
    def _net(cls, v: str) -> str:
        if v not in ("none", "bridge"):
            raise ValueError("network must be none or bridge")
        return v

    @field_validator("entrypoint")
    @classmethod
    def _entry(cls, v: str) -> str:
        if not re.fullmatch(r"[a-zA-Z0-9_]+\.py", v):
            raise ValueError("entrypoint must be a top-level .py file")
        return v


def _tree_hash(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if p.is_file():
            h.update(p.relative_to(root).as_posix().encode() + b"\0")
            h.update(hashlib.sha256(p.read_bytes()).digest())
    return h.hexdigest()


def static_analysis(source: str, filename: str, network_allowed: bool) -> list[str]:
    issues: list[str] = []
    try:
        tree = ast.parse(source, filename)
    except SyntaxError as exc:
        return [f"{filename}: syntax error: {exc}"]
    for node in ast.walk(tree):
        mods: list[str] = []
        if isinstance(node, ast.Import):
            mods = [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods = [node.module.split(".")[0]]
        for m in mods:
            if m in FORBIDDEN_MODULES and not (network_allowed and m in NETWORK_MODULES):
                issues.append(f"{filename}:{node.lineno}: import of '{m}' is not allowed")
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name) and f.id in FORBIDDEN_CALLS:
                issues.append(f"{filename}:{node.lineno}: call to '{f.id}' is not allowed")
            if isinstance(f, ast.Attribute) and f.attr in FORBIDDEN_ATTRS:
                issues.append(f"{filename}:{node.lineno}: call to '.{f.attr}()' is not allowed")
        if isinstance(node, ast.Attribute) and node.attr.startswith("__") and node.attr not in ("__name__", "__init__", "__main__", "__file__", "__dict__"):
            issues.append(f"{filename}:{node.lineno}: dunder attribute access '{node.attr}' is not allowed")
    return issues


class SkillManager:
    def __init__(self, controller: SecurityController, root: Path, sandbox: Optional[DockerSandbox] = None):
        self.ctl = controller
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.sandbox = sandbox or make_sandbox(allowed_images=(IMAGE,), workroot=self.root)
        if self.sandbox.workroot is None:
            self.sandbox.workroot = self.root
        self.index_file = self.root / "index.json"

    # ---------- index ----------
    def _index(self) -> dict:
        if self.index_file.exists():
            return json.loads(self.index_file.read_text(encoding="utf-8"))
        return {"skills": {}}

    def _save(self, idx: dict) -> None:
        tmp = self.index_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(idx, indent=2), encoding="utf-8")
        os.replace(tmp, self.index_file)

    def list(self) -> list[dict]:
        out = []
        for name, s in self._index()["skills"].items():
            out.append({"name": name, "active": s.get("active"), "previous": s.get("history", [])[-1:] or None,
                        "versions": {v: {k: d[k] for k in ("status", "sha256", "description", "capabilities", "submitted_by")}
                                     for v, d in s["versions"].items()}})
        return out

    def get(self, name: str, version: str) -> Optional[dict]:
        return self._index()["skills"].get(name, {}).get("versions", {}).get(version)

    def find_for_capability(self, need: str) -> list[dict]:
        """Capability-gap check: active skills whose description/capabilities match the need."""
        words = set(re.findall(r"[a-z0-9]{3,}", need.lower()))
        hits = []
        for name, s in self._index()["skills"].items():
            act = s.get("active")
            if not act:
                continue
            d = s["versions"][act]
            text = set(re.findall(r"[a-z0-9]{3,}", (d["description"] + " " + " ".join(d["capabilities"]) + " " + name).lower()))
            score = len(words & text)
            if score:
                hits.append({"name": name, "version": act, "score": score, "description": d["description"]})
        return sorted(hits, key=lambda h: -h["score"])

    # ---------- submit + validate ----------
    def submit(self, files: dict[str, str], submitted_by: str) -> dict:
        """Write a draft from {relative_path: text} and validate it. Returns the validation report."""
        if "skill.json" not in files:
            raise ValueError("skill.json is required")
        manifest = SkillManifest.model_validate_json(files["skill.json"])
        dest = self.root / manifest.name / manifest.version
        existing = self.get(manifest.name, manifest.version)
        if existing and existing["status"] in ("active", "approved", "superseded"):
            raise ValueError("this version is already registered; bump the version")
        if dest.exists():
            self._make_writable(dest)
            shutil.rmtree(dest)
        total = 0
        for rel, text in files.items():
            p = Path(rel)
            if p.is_absolute() or ".." in p.parts or p.suffix not in ALLOWED_SUFFIXES or len(p.parts) > 3:
                raise ValueError(f"file {rel!r} is not allowed (relative paths with {sorted(ALLOWED_SUFFIXES)} only)")
            total += len(text.encode())
            if total > MAX_TOTAL_BYTES:
                raise ValueError("skill is larger than 1 MB")
            (dest / p).parent.mkdir(parents=True, exist_ok=True)
            (dest / p).write_text(text, encoding="utf-8")
        report = self.validate(manifest, dest)
        idx = self._index()
        entry = idx["skills"].setdefault(manifest.name, {"versions": {}, "active": None, "history": []})
        entry["versions"][manifest.version] = {
            "status": "validated" if report["passed"] else "rejected", "sha256": _tree_hash(dest),
            "description": manifest.description, "capabilities": manifest.capabilities, "license": manifest.license,
            "network": manifest.network, "entrypoint": manifest.entrypoint, "timeout_s": manifest.timeout_s,
            "submitted_by": submitted_by, "submitted_at": time.time(), "report": report,
        }
        self._save(idx)
        self._make_readonly(dest)
        self.ctl.audit.append(submitted_by, "skill.submit", {"name": manifest.name, "version": manifest.version,
                                                             "passed": report["passed"], "sha256": entry["versions"][manifest.version]["sha256"]})
        return {"name": manifest.name, "version": manifest.version, **report}

    def validate(self, m: SkillManifest, d: Path) -> dict:
        checks: dict[str, dict] = {}
        entry = d / m.entrypoint
        checks["manifest"] = {"ok": entry.exists(), "detail": "ok" if entry.exists() else f"missing {m.entrypoint}"}
        checks["license"] = {"ok": True, "detail": m.license}
        bad_links = [str(p) for p in d.rglob("*") if p.is_symlink()]
        checks["files"] = {"ok": not bad_links, "detail": bad_links or "ok"}
        issues: list[str] = []
        for py in d.rglob("*.py"):
            issues += static_analysis(py.read_text(encoding="utf-8"), py.relative_to(d).as_posix(), m.network == "bridge")
        checks["static_analysis"] = {"ok": not issues, "detail": issues or "no forbidden imports or calls"}
        req = d / "requirements.txt"
        deps = [l.strip() for l in req.read_text().splitlines() if l.strip() and not l.startswith("#")] if req.exists() else []
        checks["dependencies"] = {"ok": not deps, "detail": "standard library only" if not deps else
                                  f"third-party dependencies are not supported yet: {deps}"}
        tests = list(d.glob("test_*.py"))
        if not tests:
            checks["tests"] = {"ok": False, "detail": "at least one test_*.py is required"}
        if all(c["ok"] for c in checks.values()):
            try:
                t = self.sandbox.run(SandboxSpec(image=IMAGE, command=["python", "-I", "-B", "-m", "unittest", "discover", "-s", "/work", "-p", "test_*.py"],
                                                 workdir=str(d), timeout_s=120, memory_mb=256))
                checks["tests"] = {"ok": t.exit_code == 0, "detail": (t.stderr or t.stdout)[-2000:]}
                ex = self.sandbox.run(SandboxSpec(image=IMAGE, command=["python", "-I", "-B", f"/work/{m.entrypoint}"],
                                                  workdir=str(d), timeout_s=m.timeout_s, memory_mb=256,
                                                  stdin=json.dumps(m.example_input)))
                ok = ex.exit_code == 0
                try:
                    json.loads(ex.stdout)
                except ValueError:
                    ok = False
                checks["example_run"] = {"ok": ok, "detail": (ex.stdout if ok else ex.stderr or ex.stdout)[-2000:]}
            except SandboxUnavailable as exc:
                checks["tests"] = {"ok": False, "detail": f"not run: {exc}"}
        return {"passed": all(c["ok"] for c in checks.values()), "checks": checks}

    # ---------- register (approval) ----------
    def _req(self, agent_id: str, name: str, version: str, sha: str, zone: str, approval_id: Optional[str]) -> ActionRequest:
        return ActionRequest(agent_id=agent_id, action="skill.register", zone=zone,
                             params={"name": name, "version": version, "sha256": sha}, approval_id=approval_id,
                             justification=f"register skill {name} {version}")

    def register(self, name: str, version: str, agent: dict, zone: str = "standard",
                 approval_id: Optional[str] = None) -> Verdict:
        d = self.get(name, version)
        if not d:
            raise KeyError("unknown skill version")
        if d["status"] != "validated":
            raise ValueError(f"skill is {d['status']}; only validated skills can be registered")
        cur = _tree_hash(self.root / name / version)
        if cur != d["sha256"]:
            raise ValueError("skill files changed after validation; resubmit")
        v = self.ctl.authorize(self._req(agent["agent_id"], name, version, cur, zone, approval_id), agent)
        if v.allowed:
            self._activate(name, version, agent["agent_id"])
        return v

    def _activate(self, name: str, version: str, by: str) -> None:
        idx = self._index()
        s = idx["skills"][name]
        if s["active"] and s["active"] != version:
            s["versions"][s["active"]]["status"] = "superseded"
            s["history"].append(s["active"])
        s["versions"][version]["status"] = "active"
        s["active"] = version
        self._save(idx)
        self.ctl.audit.append(by, "skill.activate", {"name": name, "version": version})

    def rollback(self, name: str, by: str = "admin") -> str:
        idx = self._index()
        s = idx["skills"].get(name)
        if not s or not s["history"]:
            raise ValueError("no previous version to roll back to")
        prev = s["history"].pop()
        if s["active"]:
            s["versions"][s["active"]]["status"] = "rolled_back"
        s["versions"][prev]["status"] = "active"
        s["active"] = prev
        self._save(idx)
        self.ctl.audit.append(by, "skill.rollback", {"name": name, "to": prev})
        return prev

    # ---------- execute ----------
    def run(self, name: str, inputs: dict, agent: dict, zone: str = "standard", mission_id: Optional[str] = None) -> dict:
        idx = self._index()
        s = idx["skills"].get(name)
        if not s or not s["active"]:
            raise KeyError(f"no active skill named {name!r}")
        ver = s["active"]
        d = s["versions"][ver]
        if _tree_hash(self.root / name / ver) != d["sha256"]:
            self.ctl.audit.append("system", "skill.integrity_failure", {"name": name, "version": ver})
            raise PermissionError("skill files do not match the approved hash; refusing to run")
        v = self.ctl.authorize(ActionRequest(agent_id=agent["agent_id"], action="skill.execute", zone=zone,
                                             mission_id=mission_id, params={"name": name, "version": ver}), agent)
        if not v.allowed:
            return {"verdict": v.to_dict(), "result": None}
        if d["network"] != "none":
            nv = self.ctl.authorize(ActionRequest(agent_id=agent["agent_id"], action="sandbox.exec", zone=zone,
                                                  mission_id=mission_id, params={"network": d["network"], "skill": name}), agent)
            if not nv.allowed:
                return {"verdict": nv.to_dict(), "result": None}
        r = self.sandbox.run(SandboxSpec(image=IMAGE, command=["python", "-I", "-B", f"/work/{d['entrypoint']}"],
                                         workdir=str(self.root / name / ver), network=d["network"],
                                         timeout_s=d["timeout_s"], memory_mb=256, stdin=json.dumps(inputs)))
        if mission_id:
            self.ctl.record_usage(mission_id, seconds=r.duration_s)
        try:
            output = json.loads(r.stdout) if r.exit_code == 0 else None
        except ValueError:
            output = None
        self.ctl.audit.append(agent["agent_id"], "skill.run", {"name": name, "version": ver, "exit_code": r.exit_code,
                                                               "duration_s": r.duration_s})
        return {"verdict": v.to_dict(), "result": {"version": ver, "exit_code": r.exit_code, "output": output,
                                                   "stderr": r.stderr[-2000:], "timed_out": r.timed_out}}

    # ---------- helpers ----------
    @staticmethod
    def _make_readonly(d: Path) -> None:
        for p in d.rglob("*"):
            if p.is_file():
                p.chmod(stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)

    @staticmethod
    def _make_writable(d: Path) -> None:
        for p in d.rglob("*"):
            if p.is_file():
                p.chmod(stat.S_IREAD | stat.S_IWRITE)
