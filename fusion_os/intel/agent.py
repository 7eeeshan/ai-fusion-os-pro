"""Technology intelligence agent: watches official sources and evaluates what it finds.

Sources (all public APIs, fetched through the security gate as the `tech-intel` research identity):
GitHub releases, Hugging Face models, arXiv, PyPI, npm, OSV advisories and the official MCP server registry.
Measurable criteria are scored from data (licence, maintenance, reliability signals, known vulnerabilities).
The rest (hardware, performance, cost, compatibility, integration, functionality) stay unscored until a benchmark or
a person fills them in: the agent does not invent numbers.
"""
from __future__ import annotations

import json
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from ..security.controller import SecurityController
from ..security.policy import ActionRequest
from .registry import TechRegistry

PERMISSIVE = {"mit", "apache-2.0", "bsd-2-clause", "bsd-3-clause", "isc", "mpl-2.0", "unlicense", "0bsd", "psf-2.0", "apache 2.0", "bsd"}
COPYLEFT = {"gpl-2.0", "gpl-3.0", "lgpl-2.1", "lgpl-3.0", "agpl-3.0"}

DEFAULT_WATCHLIST = {
    "github": ["ollama/ollama", "ggml-org/llama.cpp", "modelcontextprotocol/python-sdk", "projectdiscovery/nuclei",
               "semgrep/semgrep", "aquasecurity/trivy"],
    "pypi": ["fastapi", "httpx", "pydantic", "anthropic", "mcp"],
    "npm": ["@modelcontextprotocol/sdk"],
    "huggingface": ["gguf"],
    "arxiv": ["llm agents", "prompt injection defense"],
    "mcp_registry": True,
}


def _days_since(iso: Optional[str]) -> Optional[float]:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - dt).total_seconds() / 86400


def license_score(lic: str) -> Optional[float]:
    l = (lic or "").lower()
    if not l or l in ("unknown", "noassertion", "other"):
        return None
    if l in PERMISSIVE or any(p in l for p in ("mit", "apache", "bsd")):
        return 10.0
    if l in COPYLEFT or "gpl" in l:
        return 5.0
    return 3.0


def maintenance_score(days: Optional[float]) -> Optional[float]:
    if days is None:
        return None
    return 10.0 if days < 30 else 8.0 if days < 90 else 6.0 if days < 180 else 4.0 if days < 365 else 1.0


class TechIntelAgent:
    def __init__(self, ctl: SecurityController, registry: TechRegistry, client: Optional[httpx.Client] = None):
        self.ctl, self.reg = ctl, registry
        self.client = client or httpx.Client(timeout=20, headers={"User-Agent": "AIFusionOSPro-TechIntel/0.6"})
        tok = ctl.register_agent("tech-intel", ["research"])
        self.agent = ctl.agent_for_token(tok)

    def _get(self, url: str, **kw: Any) -> httpx.Response:
        import os
        if url.startswith("https://api.github.com/") and os.environ.get("GITHUB_TOKEN"):
            kw.setdefault("headers", {})["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
        v = self.ctl.authorize(ActionRequest(agent_id="tech-intel", action="research.web.fetch", zone="research",
                                             target=url, params={"purpose": "tech-intel"}), self.agent)
        if not v.allowed:
            raise PermissionError(v.reason)
        r = self.client.get(url, **kw)
        r.raise_for_status()
        return r

    # ---------- sources ----------
    def github(self, repo: str) -> str:
        meta = self._get(f"https://api.github.com/repos/{repo}").json()
        rel = {}
        try:
            rel = self._get(f"https://api.github.com/repos/{repo}/releases/latest").json()
        except httpx.HTTPStatusError:
            pass
        lic = (meta.get("license") or {}).get("spdx_id") or ""
        facts = {"stars": meta.get("stargazers_count"), "open_issues": meta.get("open_issues_count"),
                 "archived": meta.get("archived"), "pushed_at": meta.get("pushed_at"), "released_at": rel.get("published_at")}
        tid, _ = self.reg.upsert("repository", repo, "github", meta.get("html_url", ""), rel.get("tag_name", ""), lic, facts)
        stars = meta.get("stargazers_count") or 0
        self.reg.set_scores(tid, {"licensing": license_score(lic),
                                  "maintenance": 0.0 if meta.get("archived") else maintenance_score(_days_since(rel.get("published_at") or meta.get("pushed_at"))),
                                  "reliability": min(10.0, 2.0 + stars / 5000) if stars else None})
        return tid

    def pypi(self, name: str) -> str:
        d = self._get(f"https://pypi.org/pypi/{name}/json").json()
        info = d["info"]
        ver = info["version"]
        files = d.get("urls") or []
        released = files[0]["upload_time_iso_8601"] if files else None
        lic = info.get("license_expression") or (info.get("license") or "")[:40]
        vulns = self.osv(name, "PyPI", ver)
        tid, _ = self.reg.upsert("package", f"pypi:{name}", "pypi", f"https://pypi.org/project/{name}/", ver, lic,
                                 {"released_at": released, "requires_python": info.get("requires_python"), "known_vulns": vulns})
        self.reg.set_scores(tid, {"licensing": license_score(lic), "maintenance": maintenance_score(_days_since(released)),
                                  "security": 10.0 if not vulns else max(0.0, 10.0 - 3 * len(vulns))})
        return tid

    def npm(self, name: str) -> str:
        d = self._get(f"https://registry.npmjs.org/{name}").json()
        ver = d.get("dist-tags", {}).get("latest", "")
        released = d.get("time", {}).get(ver)
        lic = d.get("license") if isinstance(d.get("license"), str) else ""
        vulns = self.osv(name, "npm", ver)
        tid, _ = self.reg.upsert("package", f"npm:{name}", "npm", f"https://www.npmjs.com/package/{name}", ver, lic,
                                 {"released_at": released, "known_vulns": vulns})
        self.reg.set_scores(tid, {"licensing": license_score(lic), "maintenance": maintenance_score(_days_since(released)),
                                  "security": 10.0 if not vulns else max(0.0, 10.0 - 3 * len(vulns))})
        return tid

    def osv(self, name: str, ecosystem: str, version: str) -> list[str]:
        v = self.ctl.authorize(ActionRequest(agent_id="tech-intel", action="research.web.fetch", zone="research",
                                             target="https://api.osv.dev/v1/query"), self.agent)
        if not v.allowed:
            raise PermissionError(v.reason)
        r = self.client.post("https://api.osv.dev/v1/query", json={"package": {"name": name, "ecosystem": ecosystem}, "version": version})
        r.raise_for_status()
        return [x["id"] for x in r.json().get("vulns", [])]

    def huggingface(self, search: str, limit: int = 10) -> list[str]:
        items = self._get("https://huggingface.co/api/models", params={"search": search, "sort": "lastModified",
                                                                         "direction": -1, "limit": limit}).json()
        out = []
        for m in items:
            tid, _ = self.reg.upsert("model", m["id"], "huggingface", f"https://huggingface.co/{m['id']}",
                                     m.get("lastModified", "")[:10], "", {"downloads": m.get("downloads"), "likes": m.get("likes"),
                                                                          "tags": (m.get("tags") or [])[:15]})
            self.reg.set_scores(tid, {"maintenance": maintenance_score(_days_since(m.get("lastModified")))})
            out.append(tid)
        return out

    def arxiv(self, query: str, limit: int = 10) -> list[str]:
        r = self._get("https://export.arxiv.org/api/query", params={"search_query": f"all:{query}", "sortBy": "submittedDate",
                                                                    "sortOrder": "descending", "max_results": limit})
        ns = {"a": "http://www.w3.org/2005/Atom"}
        out = []
        for e in ET.fromstring(r.text).findall("a:entry", ns):
            title = " ".join(e.findtext("a:title", "", ns).split())
            tid, _ = self.reg.upsert("paper", title, "arxiv", e.findtext("a:id", "", ns), e.findtext("a:published", "", ns)[:10], "",
                                     {"summary": " ".join(e.findtext("a:summary", "", ns).split())[:600]})
            out.append(tid)
        return out

    def mcp_registry(self, limit: int = 30) -> list[str]:
        d = self._get("https://registry.modelcontextprotocol.io/v0/servers", params={"limit": limit}).json()
        out = []
        for s in d.get("servers", []):
            srv = s.get("server", s)
            tid, _ = self.reg.upsert("mcp", srv.get("name", "?"), "mcp-registry", (srv.get("repository") or {}).get("url", ""),
                                     srv.get("version", ""), "", {"description": (srv.get("description") or "")[:300]})
            out.append(tid)
        return out

    def scan(self, watchlist: Optional[dict] = None) -> dict:
        wl = watchlist or DEFAULT_WATCHLIST
        report: dict[str, Any] = {"started": time.time(), "ok": [], "errors": []}
        jobs = [("github", r, self.github) for r in wl.get("github", [])] + [("pypi", p, self.pypi) for p in wl.get("pypi", [])] + \
               [("npm", p, self.npm) for p in wl.get("npm", [])] + [("huggingface", q, self.huggingface) for q in wl.get("huggingface", [])] + \
               [("arxiv", q, self.arxiv) for q in wl.get("arxiv", [])]
        if wl.get("mcp_registry"):
            jobs.append(("mcp_registry", "servers", lambda _x: self.mcp_registry()))
        for src, item, fn in jobs:
            try:
                fn(item)
                report["ok"].append(f"{src}:{item}")
            except Exception as exc:
                report["errors"].append(f"{src}:{item}: {str(exc)[:200]}")
        self.ctl.audit.append("tech-intel", "techintel.scan", {"ok": len(report["ok"]), "errors": report["errors"][:20]})
        return report
