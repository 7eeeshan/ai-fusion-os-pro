"""Shared research helpers: HTML to text, language guess, classification, malicious-content flags, evidence store."""
from __future__ import annotations

import hashlib
import html
import json
import re
import sqlite3
import threading
import time
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Optional


class _Text(HTMLParser):
    SKIP = {"script", "style", "noscript", "template", "svg", "iframe", "object", "embed"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.skip = 0
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.skip += 1
        if tag == "title":
            self._in_title = True
        if tag in ("p", "br", "div", "li", "h1", "h2", "h3", "tr"):
            self.out.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP and self.skip:
            self.skip -= 1
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif not self.skip:
            self.out.append(data)


def html_to_text(raw: str) -> tuple[str, str]:
    p = _Text()
    try:
        p.feed(raw)
    except Exception:
        return "", re.sub(r"<[^>]+>", " ", html.unescape(raw))
    text = re.sub(r"[ \t]+", " ", "".join(p.out))
    return p.title.strip(), re.sub(r"\n\s*\n+", "\n\n", text).strip()


_LANG = {
    "en": {"the", "and", "of", "to", "is", "in", "for", "that"},
    "de": {"der", "die", "und", "das", "ist", "nicht", "mit"},
    "fr": {"le", "la", "les", "et", "est", "des", "une", "pour"},
    "es": {"el", "la", "los", "y", "es", "de", "que", "para"},
    "ru": {"и", "в", "не", "на", "что", "это", "с"},
    "ar": {"في", "من", "على", "إلى", "أن", "هذا"},
}


def guess_language(text: str) -> str:
    words = re.findall(r"\w+", text.lower()[:20000])
    if not words:
        return "unknown"
    scores = {k: sum(1 for w in words if w in v) for k, v in _LANG.items()}
    best = max(scores, key=scores.get)  # type: ignore[arg-type]
    if scores[best] >= 3:
        return best
    if re.search(r"[一-鿿]", text):
        return "zh"
    return "unknown"


CATEGORIES = {
    "ransomware": ["ransomware", "leak site", "decryptor", "ransom", "lockbit", "victim"],
    "marketplace": ["vendor", "escrow", "listing", "shipping", "market", "btc", "xmr"],
    "credential-leak": ["combo list", "combolist", "dump", "leaked database", "credentials", "stealer logs"],
    "exploit-trade": ["0day", "zero-day", "exploit for sale", "rce", "poc"],
    "forum": ["thread", "reply", "posted by", "members", "forum"],
    "news": ["journalist", "news", "press", "report", "editor"],
    "vulnerability": ["cve-", "advisory", "patch", "vulnerability", "security update"],
}


def classify(text: str) -> list[str]:
    t = text.lower()
    hits = [(c, sum(t.count(k) for k in kws)) for c, kws in CATEGORIES.items()]
    return [c for c, n in sorted(hits, key=lambda x: -x[1]) if n >= 2][:3] or ["uncategorized"]


_FLAGS = [
    ("executable-content", re.compile(r"(MZ\x90|\x7fELF|powershell\s+-e(nc)?\s|<script[^>]*>\s*eval\(|document\.write\(unescape)", re.I)),
    ("credential-material", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+:[^\s:]{4,}\b")),
    ("crypto-wallet", re.compile(r"\b(bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b")),
    ("download-lure", re.compile(r"\b(download|run|open)\b.{0,40}\.(exe|scr|bat|ps1|vbs|jar|apk|msi|dll)\b", re.I)),
]


def risk_flags(text: str) -> list[str]:
    return [name for name, pat in _FLAGS if pat.search(text)]


def redact_credentials(text: str) -> str:
    """Never keep third-party credentials found during research."""
    return _FLAGS[1][1].sub("[credential redacted]", text)


class EvidenceStore:
    """Evidence records (URL, time, hash, classification). Kept apart from memory and from other research data."""

    def __init__(self, path: Path):
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("CREATE TABLE IF NOT EXISTS evidence (id TEXT PRIMARY KEY, url TEXT, source_type TEXT, "
                          "fetched REAL, sha256 TEXT, title TEXT, language TEXT, categories TEXT, flags TEXT, "
                          "injection TEXT, excerpt TEXT, translation TEXT, agent_id TEXT)")

    def add(self, url: str, source_type: str, text: str, title: str, meta: dict, agent_id: str) -> dict:
        sha = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        rec = {"id": "evd_" + sha[:16], "url": url, "source_type": source_type, "fetched": time.time(), "sha256": sha,
               "title": title[:300], "language": meta.get("language"), "categories": meta.get("categories", []),
               "flags": meta.get("flags", []), "injection": meta.get("injection", []), "excerpt": text[:1500],
               "translation": meta.get("translation"), "agent_id": agent_id}
        with self.lock:
            self.conn.execute("INSERT OR REPLACE INTO evidence VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                              tuple(json.dumps(v) if isinstance(v, list) else v for v in rec.values()))
        return rec

    def list(self, source_type: Optional[str] = None, limit: int = 200) -> list[dict[str, Any]]:
        q = "SELECT * FROM evidence" + (" WHERE source_type=?" if source_type else "") + " ORDER BY fetched DESC LIMIT ?"
        rows = self.conn.execute(q, ((source_type,) if source_type else ()) + (limit,))
        out = []
        for r in rows:
            d = dict(r)
            for k in ("categories", "flags", "injection"):
                d[k] = json.loads(d[k] or "[]")
            out.append(d)
        return out
