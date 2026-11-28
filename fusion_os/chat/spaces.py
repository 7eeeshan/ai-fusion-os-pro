"""Projects, like in the Claude desktop app: a named place for related chats with its own instructions and
knowledge files. Every chat in a project gets the project's instructions, and its knowledge: in full when it is
small, otherwise the passages that best match the request (plus a tool to read any file in full).

Stored in <data>/projects/<id>/project.json and <data>/projects/<id>/files/<name>. Only text is kept; the person
adds files from the interface, so they are their own words and documents, but they are still passed to the model
as untrusted text (a document can contain instructions that are not the person's).
"""
from __future__ import annotations

import json
import re
import shutil
import time
import uuid
from pathlib import Path
from typing import Optional

MAX_FILE = 2_000_000
MAX_FILES = 200
MAX_TOTAL = 40_000_000
FULL_BUDGET = 24_000  # characters of knowledge put in the prompt in full (fits the local model's 32k context)
CHUNK = 1_500
NAME = re.compile(r"^[^\\/:*?\"<>|\x00-\x1f]{1,120}$")
_WORD = re.compile(r"[a-z0-9]{3,}")


class SpaceError(ValueError):
    pass


def _words(t: str) -> list[str]:
    return _WORD.findall(t.lower())


class Spaces:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def _dir(self, sid: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{12}", sid or ""):
            raise KeyError(sid)
        d = self.root / sid
        if not (d / "project.json").is_file():
            raise KeyError(sid)
        return d

    def _meta(self, sid: str) -> dict:
        return json.loads((self._dir(sid) / "project.json").read_text(encoding="utf-8"))

    def _write(self, sid: str, meta: dict) -> None:
        d = self.root / sid
        tmp = d / "project.tmp"
        tmp.write_text(json.dumps(meta, indent=1), encoding="utf-8")
        tmp.replace(d / "project.json")

    def files(self, sid: str) -> list[dict]:
        f = self._dir(sid) / "files"
        if not f.is_dir():
            return []
        return [{"name": p.name, "size": p.stat().st_size} for p in sorted(f.iterdir()) if p.is_file()]

    def _public(self, sid: str) -> dict:
        m = self._meta(sid)
        fs = self.files(sid)
        return {**m, "files": fs, "size": sum(x["size"] for x in fs)}

    # ---------- projects ----------
    def list(self) -> list[dict]:
        out = []
        for d in self.root.iterdir():
            if (d / "project.json").is_file():
                try:
                    out.append(self._public(d.name))
                except (KeyError, OSError, ValueError):
                    continue
        return sorted(out, key=lambda m: m.get("updated", 0), reverse=True)

    def get(self, sid: str) -> dict:
        return self._public(sid)

    def create(self, name: str, description: str = "", instructions: str = "") -> dict:
        name = " ".join((name or "").split())[:120]
        if not name:
            raise SpaceError("a project needs a name")
        sid = uuid.uuid4().hex[:12]
        (self.root / sid / "files").mkdir(parents=True)
        now = time.time()
        self._write(sid, {"id": sid, "name": name, "description": description[:2000],
                          "instructions": instructions[:40000], "created": now, "updated": now})
        return self._public(sid)

    def update(self, sid: str, name: Optional[str] = None, description: Optional[str] = None,
               instructions: Optional[str] = None) -> dict:
        m = self._meta(sid)
        if name is not None:
            n = " ".join(name.split())[:120]
            if not n:
                raise SpaceError("a project needs a name")
            m["name"] = n
        if description is not None:
            m["description"] = description[:2000]
        if instructions is not None:
            m["instructions"] = instructions[:40000]
        m["updated"] = time.time()
        self._write(sid, m)
        return self._public(sid)

    def delete(self, sid: str) -> bool:
        d = self._dir(sid)
        shutil.rmtree(d)
        return True

    # ---------- knowledge ----------
    def add_file(self, sid: str, name: str, content: str) -> dict:
        d = self._dir(sid) / "files"
        name = (name or "").strip().replace("\\", "/").split("/")[-1]
        if not NAME.match(name) or name in (".", ".."):
            raise SpaceError("bad file name")
        data = content.encode("utf-8")
        if len(data) > MAX_FILE:
            raise SpaceError("file is too large (2 MB of text at most)")
        cur = self.files(sid)
        if len(cur) >= MAX_FILES and name not in {f["name"] for f in cur}:
            raise SpaceError("a project holds 200 files at most")
        if sum(f["size"] for f in cur if f["name"] != name) + len(data) > MAX_TOTAL:
            raise SpaceError("the project's knowledge is full (40 MB)")
        d.mkdir(exist_ok=True)
        (d / name).write_bytes(data)
        self.update(sid)
        return {"name": name, "size": len(data)}

    def read_file(self, sid: str, name: str) -> str:
        d = (self._dir(sid) / "files").resolve()
        f = (d / name).resolve()
        if not f.is_relative_to(d) or not f.is_file():
            raise KeyError(name)
        return f.read_text(encoding="utf-8", errors="replace")

    def remove_file(self, sid: str, name: str) -> bool:
        d = (self._dir(sid) / "files").resolve()
        f = (d / name).resolve()
        if not f.is_relative_to(d) or not f.is_file():
            raise KeyError(name)
        f.unlink()
        self.update(sid)
        return True

    def knowledge(self, sid: str, query: str, budget: int = FULL_BUDGET) -> tuple[list[tuple[str, str]], bool]:
        """[(file, text)] for the prompt, and whether that is all of it (False: best matching passages only)."""
        docs = [(f["name"], self.read_file(sid, f["name"])) for f in self.files(sid)]
        if sum(len(t) for _, t in docs) <= budget:
            return docs, True
        q = set(_words(query))
        chunks = []
        for name, text in docs:
            for i in range(0, len(text), CHUNK):
                part = text[i:i + CHUNK + 200]
                w = _words(part)
                score = sum(1 for x in w if x in q) / (1 + len(w) ** 0.5) if q else 0
                chunks.append((score, -i, name, part))
        chunks.sort(key=lambda c: (c[0], c[1]), reverse=True)
        out, used = [], 0
        for score, _, name, part in chunks:
            if used + len(part) > budget:
                break
            out.append((name, part))
            used += len(part)
        return out, False
