"""The app changing its own interface.

The assistant can read the app's own pages (chat.html, dashboard.html) and propose exact edits to them. Each change:
- is checked automatically (the page must still be complete HTML with its core parts; added lines may not touch
  approvals, policy, tokens, eval or outside web addresses, so a UI change can never weaken a guardrail);
- is an `app.ui.change` action: the person approves it after seeing the diff (never auto-approved);
- is saved as a new version in <data>/app_overlay, never over the installed files, so it survives updates and every
  version can be restored. "Original interface" (/app?safe=1, also in the tray) always serves the installed page.
Python code (the server, the security controller, policy) is not editable this way.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import time
from html.parser import HTMLParser
from importlib import resources
from pathlib import Path
from typing import Optional

from .code import CodeTools

PAGES = {"chat.html": "/app", "dashboard.html": "/dashboard"}
MAX_PAGE = 2_000_000
# Parts each page must keep so the app still works (and the person can still approve, undo and reach the original).
REQUIRED = {
    "chat.html": ["<html", "</html>", "<script", "function api(", "function send(", "function decide("],
    "dashboard.html": ["<html", "</html>", "<script"],
}
# Added lines may not contain these: they would let a UI change act on approvals, the policy or tokens by itself,
# run generated code, or talk to the internet.
FORBIDDEN = [
    (r"/approve|approvals|decide\s*\(", "approvals"),
    (r"/policy|/admin/security|security\.controller", "the security policy"),
    (r"token|localStorage|sessionStorage|document\.cookie|Authorization", "tokens and stored credentials"),
    (r"\beval\s*\(|new\s+Function|\bimport\s*\(|setTimeout\s*\(\s*['\"`]|srcdoc", "running generated code"),
    (r"(?:https?:)?//(?!127\.0\.0\.1|localhost)[a-z0-9.-]+\.[a-z]{2,}", "outside web addresses"),
    (r"<iframe|<object|<embed|<base\b|http-equiv", "embedding or redirecting the page"),
]
BANNER = ('<div id="fos-custom-ui" style="position:fixed;right:8px;bottom:6px;z-index:99999;font:12px system-ui;'
          'opacity:.55;background:rgba(127,127,127,.15);padding:2px 8px;border-radius:8px">Customised interface '
          'v{v} · <a href="{path}?safe=1">original</a></div>')


class UIChangeError(ValueError):
    pass


def original(page: str) -> str:
    return resources.files("fusion_os.api").joinpath(page).read_text(encoding="utf-8")


class _Tags(HTMLParser):
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.problems: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in self.VOID:
            return
        if tag in self.stack:
            while self.stack and self.stack.pop() != tag:
                pass  # browsers close unclosed inner tags too; only a missing opener is a problem
        else:
            self.problems.append(f"</{tag}> has no opening tag")


def check(page: str, old: str, new: str) -> list[str]:
    """Problems with a proposed version of a page (empty = it passes)."""
    out = [f"the page lost a required part: {r}" for r in REQUIRED.get(page, []) if r in old and r not in new]
    if len(new.encode("utf-8")) > MAX_PAGE:
        out.append("the page is too large")
    for tag in ("script", "style"):
        if new.count(f"<{tag}") != new.count(f"</{tag}>"):
            out.append(f"<{tag}> and </{tag}> tags don't match")
    p = _Tags()
    try:
        p.feed(new)
        p.close()
    except Exception as exc:  # HTMLParser is lenient; this is only a backstop
        out.append(f"HTML could not be read: {exc}")
    out += p.problems[:5]
    old_lines = set(old.splitlines())
    added = [ln for ln in new.splitlines() if ln not in old_lines]
    for ln in added:
        for rx, what in FORBIDDEN:
            if re.search(rx, ln, re.I):
                out.append(f"an added line touches {what}, which interface changes may not do: {ln.strip()[:160]}")
                break
    was_ok = not any(_unbalanced(x) for x in re.findall(r"<script[^>]*>(.*?)</script>", old, re.S))
    for script in re.findall(r"<script[^>]*>(.*?)</script>", new, re.S) if was_ok else []:
        if _unbalanced(script):
            out.append("a script block has unbalanced brackets or an unclosed string")
            break
    return out


def _unbalanced(js: str) -> bool:
    """Light JS check: brackets balance outside strings, comments and template literals (regex literals are rare
    in these pages and mostly balanced; a bracket inside one could give a false alarm, which only blocks a change)."""
    pairs, stack, i, n = {")": "(", "]": "[", "}": "{"}, [], 0, len(js)
    while i < n:
        c = js[i]
        if c in "'\"`":
            q, i = c, i + 1
            while i < n and js[i] != q:
                if js[i] == "\\":
                    i += 1
                elif q == "`" and js.startswith("${", i):  # template expression: balance it as code
                    depth, i = 1, i + 2
                    while i < n and depth:
                        depth += {"{": 1, "}": -1}.get(js[i], 0)
                        i += 1
                    continue
                elif q != "`" and js[i] == "\n":
                    return True
                i += 1
            if i >= n:
                return True
        elif js.startswith("//", i):
            j = js.find("\n", i)
            i = n if j < 0 else j
        elif js.startswith("/*", i):
            j = js.find("*/", i + 2)
            if j < 0:
                return True
            i = j + 1
        elif c == "/" and _regex_ok(js, i):  # regex literal: skip to its closing slash
            i += 1
            in_class = False
            while i < n and (js[i] != "/" or in_class):
                if js[i] == "\\":
                    i += 1
                elif js[i] == "[":
                    in_class = True
                elif js[i] == "]":
                    in_class = False
                elif js[i] == "\n":
                    return True
                i += 1
        elif c in "([{":
            stack.append(c)
        elif c in ")]}":
            if not stack or stack.pop() != pairs[c]:
                return True
        i += 1
    return bool(stack)


def _regex_ok(js: str, i: int) -> bool:
    j = i - 1
    while j >= 0 and js[j] in " \t\r\n":
        j -= 1
    if j < 0 or js[j] in "(,=:[!&|?{};+-*%<>~^":
        return True
    m = re.search(r"([A-Za-z_$]+)$", js[max(0, j - 10):j + 1])
    return bool(m and m.group(1) in ("return", "typeof", "case", "in", "of", "void", "delete", "throw"))


class AppOverlay:
    """Versions of the app's pages, kept in <data>/app_overlay/<page>/v<N>.html with a manifest."""

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def _manifest_path(self) -> Path:
        return self.root / "manifest.json"

    def manifest(self) -> dict:
        try:
            return json.loads(self._manifest_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save(self, m: dict) -> None:
        tmp = self._manifest_path().with_suffix(".tmp")
        tmp.write_text(json.dumps(m, indent=1), encoding="utf-8")
        tmp.replace(self._manifest_path())

    def current(self, page: str) -> tuple[str, int]:
        """The page as the app serves it now, and its version (0 = the installed original)."""
        e = self.manifest().get(page) or {}
        v = int(e.get("active") or 0)
        if v:
            f = self.root / page.removesuffix(".html") / f"v{v}.html"
            try:
                return f.read_text(encoding="utf-8"), v
            except OSError:
                pass
        return original(page), 0

    def serve(self, page: str, safe: bool = False) -> str:
        if safe:
            return original(page)
        text, v = self.current(page)
        if not v:
            return text
        banner = BANNER.format(v=v, path=PAGES[page])
        return text.replace("</body>", banner + "</body>", 1) if "</body>" in text else text + banner

    def plan(self, page: str, edits: list[dict]) -> dict:
        if page not in PAGES:
            raise UIChangeError(f"only these pages can change: {', '.join(PAGES)}")
        old, v = self.current(page)
        new = old
        if not edits:
            raise UIChangeError("give at least one edit: {old, new}")
        for e in edits[:20]:
            o, nw = str(e.get("old") or ""), str(e.get("new") or "")
            if not o:
                raise UIChangeError("each edit needs the exact old text to replace (read the page first)")
            c = new.count(o)
            if c != 1:
                raise UIChangeError(f"old text found {c} times; it must appear exactly once: {o[:120]}")
            new = new.replace(o, nw, 1)
        if new == old:
            raise UIChangeError("the edits change nothing")
        problems = check(page, old, new)
        if problems:
            raise UIChangeError("the change failed its checks:\n- " + "\n- ".join(problems))
        return {"page": page, "base_version": v, "sha256": hashlib.sha256(new.encode()).hexdigest(), "new": new,
                "diff": CodeTools.diff(page, old, new)}

    def apply(self, plan: dict, note: str = "") -> int:
        if hashlib.sha256(plan["new"].encode()).hexdigest() != plan["sha256"]:
            raise UIChangeError("content changed after it was approved")
        if self.current(plan["page"])[1] != plan["base_version"]:
            raise UIChangeError("the page changed since this was proposed; propose it again")
        m = self.manifest()
        e = m.setdefault(plan["page"], {"active": 0, "versions": []})
        v = max([0] + [x["v"] for x in e["versions"]]) + 1
        d = self.root / plan["page"].removesuffix(".html")
        d.mkdir(parents=True, exist_ok=True)
        (d / f"v{v}.html").write_text(plan["new"], encoding="utf-8")
        e["versions"].append({"v": v, "from": plan["base_version"], "at": time.time(), "note": note[:300]})
        e["active"] = v
        self._save(m)
        return v

    def activate(self, page: str, v: int) -> int:
        """Switch to an earlier version (0 = original). Undo is activate(<previous>)."""
        m = self.manifest()
        e = m.get(page) or {"active": 0, "versions": []}
        if v and v not in [x["v"] for x in e["versions"]]:
            raise UIChangeError(f"no version {v} of {page}")
        e["active"] = int(v)
        m[page] = e
        self._save(m)
        return v

    def undo(self, page: str) -> int:
        e = self.manifest().get(page) or {}
        cur = int(e.get("active") or 0)
        prev = next((x["from"] for x in e.get("versions", []) if x["v"] == cur), 0)
        return self.activate(page, prev)

    def history(self) -> dict:
        m = self.manifest()
        return {p: {"active": (m.get(p) or {}).get("active", 0), "versions": (m.get(p) or {}).get("versions", [])}
                for p in PAGES}

    def reset(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)
        self.root.mkdir(parents=True, exist_ok=True)


def read_page(text: str, start: int = 1, end: Optional[int] = None, pattern: str = "") -> str:
    lines = text.splitlines()
    if pattern:
        try:
            rx = re.compile(pattern, re.I)
        except re.error as exc:
            raise UIChangeError(f"bad pattern: {exc}") from exc
        hits = [f"{i:>5}  {ln[:240]}" for i, ln in enumerate(lines, 1) if rx.search(ln)]
        return "\n".join(hits[:200]) or "no matches"
    start = max(1, int(start or 1))
    end = min(len(lines), int(end) if end else start + 299)
    body = "\n".join(f"{i:>5}  {lines[i - 1]}" for i in range(start, end + 1))
    more = f"\n... ({len(lines) - end} more lines)" if end < len(lines) else ""
    return body + more
