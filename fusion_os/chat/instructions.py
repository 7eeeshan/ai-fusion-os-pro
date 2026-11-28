"""Instruction skills in the same format as Claude's: a folder with a SKILL.md whose front matter has a name and a
description, plus any reference files it mentions.

The chat lists enabled skills by name and description; the model reads a skill's full instructions when it needs
them (or the person picks one for a message). Scripts inside a skill folder are kept but never run from here;
runnable skills go through the sandboxed skill system instead. Skill text is scanned for prompt-injection
patterns when it is added, and the findings are shown.
"""
from __future__ import annotations

import base64
import io
import json
import os
import re
import shutil
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import Optional

from .. import paths
from ..security.untrusted import scan

NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
MAX_FILE = 2_000_000
MAX_TOTAL = 20_000_000
TEXT_EXT = {".md", ".txt", ".json", ".yaml", ".yml", ".csv", ".py", ".js", ".ts", ".sh", ".ps1", ".html", ".css",
            ".xml", ".toml", ".ini", ".sql", ".r", ".rb", ".go", ".java", ".c", ".h", ".cpp", ".rs", ".tex"}


def parse_skill_md(text: str) -> tuple[dict, str]:
    """Front matter (simple `key: value` lines, as Claude's skills use) and the body."""
    text = text.lstrip("﻿")
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", text, re.S)
    if not m:
        return {}, text
    meta: dict = {}
    key = None
    for line in m.group(1).splitlines():
        kv = re.match(r"^([A-Za-z_][\w-]*)\s*:\s*(.*)$", line)
        if kv:
            key = kv.group(1).lower()
            meta[key] = kv.group(2).strip().strip('"').strip("'")
        elif key and line.startswith((" ", "\t")):  # folded continuation
            meta[key] = (meta[key] + " " + line.strip()).strip()
    return meta, m.group(2)


def _norm_name(s: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", s.lower()).strip("-")[:64]


class InstructionSkills:
    def __init__(self, root: Optional[Path] = None):
        self.root = root or (paths.home() / "instruction_skills")
        self.root.mkdir(parents=True, exist_ok=True)
        self.state_file = self.root / "_state.json"

    def _state(self) -> dict:
        try:
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save_state(self, st: dict) -> None:
        self.state_file.write_text(json.dumps(st, indent=2), encoding="utf-8")

    # ---------- read ----------
    def list(self) -> list[dict]:
        st = self._state()
        out = []
        for d in sorted(p for p in self.root.iterdir() if p.is_dir()):
            f = d / "SKILL.md"
            if not f.is_file():
                continue
            meta, body = parse_skill_md(f.read_text(encoding="utf-8", errors="replace"))
            s = st.get(d.name, {})
            out.append({"name": d.name, "title": meta.get("name", d.name), "description": meta.get("description", ""),
                        "enabled": s.get("enabled", True), "source": s.get("source", ""), "added": s.get("added"),
                        "warnings": s.get("warnings", []),
                        "files": sorted(p.relative_to(d).as_posix() for p in d.rglob("*") if p.is_file())[:200],
                        "size": len(body)})
        return out

    def enabled(self) -> list[dict]:
        return [s for s in self.list() if s["enabled"]]

    def read(self, name: str, file: str = "SKILL.md") -> str:
        d = (self.root / name).resolve()
        if not NAME.match(name) or not d.is_dir():
            raise KeyError(name)
        f = (d / file).resolve()
        if not f.is_relative_to(d) or not f.is_file():
            raise KeyError(file)
        text = f.read_text(encoding="utf-8", errors="replace")
        return parse_skill_md(text)[1] if file == "SKILL.md" else text

    # ---------- write ----------
    def _install(self, files: dict[str, bytes], source: str) -> dict:
        if "SKILL.md" not in files:
            raise ValueError("a skill needs a SKILL.md at its top level")
        total = sum(len(b) for b in files.values())
        if total > MAX_TOTAL:
            raise ValueError("skill is too large")
        meta, body = parse_skill_md(files["SKILL.md"].decode("utf-8", "replace"))
        name = _norm_name(meta.get("name", ""))
        if not name or not NAME.match(name):
            raise ValueError("SKILL.md front matter needs a name (letters, digits and dashes)")
        if not meta.get("description"):
            raise ValueError("SKILL.md front matter needs a description")
        dest = self.root / name
        tmp = self.root / f".{name}.tmp"
        shutil.rmtree(tmp, ignore_errors=True)
        warnings = []
        for rel, data in files.items():
            pp = PurePosixPath(rel)
            if pp.is_absolute() or ".." in pp.parts or rel.startswith(("/", "\\")) or ":" in rel:
                raise ValueError(f"bad path in skill: {rel!r}")
            if len(data) > MAX_FILE:
                raise ValueError(f"{rel} is too large")
            out = tmp / Path(*pp.parts)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)
            if pp.suffix.lower() in TEXT_EXT:
                for f in scan(data.decode("utf-8", "replace")):
                    warnings.append(f"{rel}: possible {f.kind} ({f.excerpt[:80]})")
        shutil.rmtree(dest, ignore_errors=True)
        os.replace(tmp, dest)
        st = self._state()
        st[name] = {"enabled": True, "source": source, "added": time.time(), "warnings": warnings[:20]}
        self._save_state(st)
        return next(s for s in self.list() if s["name"] == name)

    def add_text(self, skill_md: str, source: str = "manual") -> dict:
        return self._install({"SKILL.md": skill_md.encode("utf-8")}, source)

    def add_zip(self, data_b64: str, source: str = "upload") -> dict:
        raw = base64.b64decode(data_b64, validate=False)
        if len(raw) > MAX_TOTAL:
            raise ValueError("zip is too large")
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            names = [i for i in z.infolist() if not i.is_dir()]
            if sum(i.file_size for i in names) > MAX_TOTAL:
                raise ValueError("skill is too large when unpacked")
            skill_md = [i.filename for i in names if PurePosixPath(i.filename).name == "SKILL.md"]
            if not skill_md:
                raise ValueError("no SKILL.md in the zip")
            top = str(PurePosixPath(min(skill_md, key=len)).parent)
            prefix = "" if top == "." else top + "/"
            files = {i.filename[len(prefix):]: z.read(i) for i in names
                     if i.filename.startswith(prefix) and "__MACOSX" not in i.filename}
        return self._install(files, source)

    def add_folder(self, folder: Path, source: str) -> dict:
        files = {p.relative_to(folder).as_posix(): p.read_bytes() for p in folder.rglob("*")
                 if p.is_file() and not p.is_symlink()}
        return self._install(files, source)

    def set_enabled(self, name: str, enabled: bool) -> None:
        if not (self.root / name / "SKILL.md").is_file():
            raise KeyError(name)
        st = self._state()
        st.setdefault(name, {})["enabled"] = bool(enabled)
        self._save_state(st)

    def remove(self, name: str) -> bool:
        if not NAME.match(name):
            return False
        d = self.root / name
        if not d.is_dir():
            return False
        shutil.rmtree(d)
        st = self._state()
        st.pop(name, None)
        self._save_state(st)
        return True


def claude_skill_folders(env: Optional[dict] = None) -> list[Path]:
    """Skill folders Claude Code keeps for this user (~/.claude/skills/<name>/SKILL.md). Only read."""
    env = os.environ if env is None else env
    home = Path(env.get("USERPROFILE") or env.get("HOME") or Path.home())
    roots = [home / ".claude" / "skills"]
    out = []
    for r in roots:
        if r.is_dir():
            out += sorted(d for d in r.iterdir() if (d / "SKILL.md").is_file())
    return out
