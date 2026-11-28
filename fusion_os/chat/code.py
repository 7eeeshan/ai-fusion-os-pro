"""Coding tools for the chat: read, search and change files in a project folder, and run code on a copy of it.

- The project folder is chosen by the person for each chat (default: the app's workspace folder). Every path is
  resolved and must stay inside it; symlinks that lead out are refused. The app's own data folder (policy, tokens,
  audit log) can never be a project, so the assistant cannot edit its own guardrails.
- Reading and searching are allowed. Writing is `files.write` (the person approves each change, shown as a diff)
  unless the person turned on auto-approve for that chat (`files.write.preapproved`).
- Running code is `code.run` (approved per run, or `code.run.preapproved` with auto-approve). Code runs in the
  sandbox without network, on a throwaway copy of the project, so a run cannot change the person's files.
"""
from __future__ import annotations

import difflib
import fnmatch
import hashlib
import os
import re
import shutil
import secrets
from pathlib import Path
from typing import Optional

from ..sandbox import SandboxSpec

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache",
             ".tox", "dist", "build", ".next", "target", ".idea", ".vs"}
MAX_READ = 400_000
MAX_WRITE = 1_000_000
MAX_COPY_BYTES = 200 * 1024 * 1024
MAX_COPY_FILES = 20_000
IMAGE = "python:3.12-slim"


class CodeError(ValueError):
    pass


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def check_project(folder: str, data_home: Path, workspace: Path) -> Path:
    """The folder as a resolved project root, or CodeError if it may not be one."""
    if not folder or not folder.strip():
        raise CodeError("no project folder set")
    root = Path(os.path.expandvars(os.path.expanduser(folder.strip()))).resolve()
    if not root.is_dir():
        raise CodeError(f"{root} is not a folder")
    if root.parent == root:
        raise CodeError("a whole drive can't be a project folder; pick a folder inside it")
    home = data_home.resolve()
    ws = workspace.resolve()
    if root == home or root in home.parents:
        raise CodeError("this folder contains the app's own data (policy, tokens, audit log); pick another one")
    if home in root.parents and not (root == ws or ws in root.parents):
        raise CodeError("folders inside the app's data folder can't be projects, except the workspace folder")
    return root


class CodeTools:
    def __init__(self, sandbox, runs_root: Path):
        self.sandbox = sandbox
        self.runs_root = runs_root.resolve()
        self.runs_root.mkdir(parents=True, exist_ok=True)
        if getattr(self.sandbox, "workroot", None) is None:
            self.sandbox.workroot = self.runs_root

    # ---------- paths ----------
    @staticmethod
    def path(root: Path, rel: str) -> Path:
        rel = (rel or "").replace("\\", "/").strip()
        if re.match(r"^[A-Za-z]:", rel) or rel.startswith("//"):
            raise CodeError("use a path relative to the project folder")
        p = (root / rel.lstrip("/")).resolve()
        if p != root and root not in p.parents:
            raise CodeError("path is outside the project folder")
        parts = p.relative_to(root).parts
        if ".git" in parts:
            raise CodeError("the .git folder is off limits")
        return p

    @staticmethod
    def _rel(root: Path, p: Path) -> str:
        return p.relative_to(root).as_posix() or "."

    def _walk(self, root: Path, start: Path):
        for dirpath, dirnames, filenames in os.walk(start):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".") or d in (".github",))
            for f in sorted(filenames):
                p = Path(dirpath) / f
                if p.is_symlink():
                    try:
                        if root not in p.resolve().parents:
                            continue
                    except OSError:
                        continue
                yield p

    # ---------- read ----------
    def list_files(self, root: Path, rel: str = "", limit: int = 400) -> str:
        start = self.path(root, rel)
        if start.is_file():
            return self._rel(root, start)
        out = []
        for p in self._walk(root, start):
            try:
                size = p.stat().st_size
            except OSError:
                continue
            out.append(f"{self._rel(root, p)}  ({size} bytes)")
            if len(out) >= limit:
                out.append(f"... (stopped at {limit} files; list a subfolder)")
                break
        return "\n".join(out) or "(empty)"

    @staticmethod
    def _text(p: Path) -> str:
        if not p.is_file():
            raise CodeError(f"{p.name} is not a file")
        data = p.read_bytes()
        if len(data) > MAX_READ * 4:
            raise CodeError(f"{p.name} is too large to read ({len(data)} bytes)")
        if b"\x00" in data[:8000]:
            raise CodeError(f"{p.name} looks like a binary file")
        return data.decode("utf-8", errors="replace")

    def read_file(self, root: Path, rel: str, start: int = 1, end: Optional[int] = None) -> str:
        lines = self._text(self.path(root, rel)).splitlines()
        start = max(1, int(start or 1))
        end = min(len(lines), int(end) if end else start + 1999)
        body = "\n".join(f"{i:>5}  {lines[i - 1]}" for i in range(start, end + 1))
        more = f"\n... ({len(lines) - end} more lines; read from line {end + 1})" if end < len(lines) else ""
        return (body + more)[:MAX_READ] or "(empty file)"

    def search(self, root: Path, pattern: str, rel: str = "", glob: str = "", limit: int = 200) -> str:
        try:
            rx = re.compile(pattern)
        except re.error as exc:
            raise CodeError(f"bad pattern: {exc}") from exc
        out = []
        for p in self._walk(root, self.path(root, rel)):
            if glob and not fnmatch.fnmatch(p.name, glob) and not fnmatch.fnmatch(self._rel(root, p), glob):
                continue
            try:
                if p.stat().st_size > MAX_READ:
                    continue
                text = p.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for n, line in enumerate(text.splitlines(), 1):
                if rx.search(line):
                    out.append(f"{self._rel(root, p)}:{n}: {line.strip()[:240]}")
                    if len(out) >= limit:
                        return "\n".join(out) + f"\n... (stopped at {limit} matches)"
        return "\n".join(out) or "no matches"

    # ---------- write ----------
    def plan_write(self, root: Path, rel: str, content: str) -> dict:
        """What writing `content` to `rel` would change: {path, new, diff, sha256, created}."""
        if len(content.encode("utf-8")) > MAX_WRITE:
            raise CodeError("file is too large to write from the chat")
        p = self.path(root, rel)
        if p.is_dir():
            raise CodeError(f"{rel} is a folder")
        old = self._text(p) if p.exists() else ""
        return {"path": self._rel(root, p), "new": content, "sha256": sha(content), "created": not p.exists(),
                "diff": self.diff(self._rel(root, p), old, content, not p.exists())}

    def plan_edit(self, root: Path, rel: str, old: str, new: str, replace_all: bool = False) -> dict:
        p = self.path(root, rel)
        text = self._text(p)
        if not old:
            raise CodeError("old text is empty; use write_file to create or replace a whole file")
        n = text.count(old)
        if n == 0:
            raise CodeError("old text not found in the file; read it again and copy the text exactly")
        if n > 1 and not replace_all:
            raise CodeError(f"old text appears {n} times; add more surrounding lines or set replace_all")
        updated = text.replace(old, new) if replace_all else text.replace(old, new, 1)
        out = self.plan_write(root, rel, updated)
        out["created"] = False
        return out

    @staticmethod
    def diff(rel: str, old: str, new: str, created: bool = False) -> str:
        d = difflib.unified_diff(old.splitlines(), new.splitlines(), "/dev/null" if created else f"a/{rel}",
                                 f"b/{rel}", lineterm="", n=3)
        text = "\n".join(d)
        return text if len(text) < 60_000 else text[:60_000] + "\n... (diff cut)"

    def apply(self, root: Path, plan: dict) -> str:
        p = self.path(root, plan["path"])
        if sha(plan["new"]) != plan["sha256"]:
            raise CodeError("content changed after it was approved")
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".fos-tmp")
        with open(tmp, "w", encoding="utf-8", newline="") as fh:
            fh.write(plan["new"])
        os.replace(tmp, p)
        return plan["path"]

    # ---------- run ----------
    def _stage(self, root: Path) -> Path:
        dst = self.runs_root / ("run-" + secrets.token_hex(6))
        total = files = 0
        for p in self._walk(root, root):
            try:
                size = p.stat().st_size
            except OSError:
                continue
            total += size
            files += 1
            if total > MAX_COPY_BYTES or files > MAX_COPY_FILES:
                shutil.rmtree(dst, ignore_errors=True)
                raise CodeError("the project is too large to copy for a run (over 200 MB or 20,000 files)")
            t = dst / p.relative_to(root)
            t.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, t)
        dst.mkdir(parents=True, exist_ok=True)
        return dst

    @staticmethod
    def command(code: str = "", script: str = "", args: Optional[list] = None) -> list[str]:
        args = [str(a) for a in (args or [])]
        if code and script:
            raise CodeError("give either code or script, not both")
        if code:
            return ["python", "-c", code, *args]
        if script:
            s = script.replace("\\", "/").lstrip("/")
            if script.startswith("-m "):
                return ["python", "-m", script[3:].strip(), *args]
            return ["python", "/work/" + s, *args]
        raise CodeError("give code to run, or a script path in the project")

    def run(self, root: Path, cmd: list[str], timeout_s: float = 60) -> dict:
        work = self._stage(root)
        try:
            spec = SandboxSpec(image=IMAGE, command=cmd, network="none", timeout_s=max(1, min(float(timeout_s), 300)),
                               memory_mb=1024, cpus=1.0, workdir=str(work), workdir_writable=True)
            res = self.sandbox.run(spec)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        return {"exit_code": res.exit_code, "stdout": res.stdout[-30_000:], "stderr": res.stderr[-15_000:],
                "timed_out": res.timed_out, "duration_s": round(res.duration_s, 2)}
