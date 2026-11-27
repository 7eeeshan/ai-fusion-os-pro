"""Authorized security engagements: who authorized testing, of what targets, with which tools, until when.

Active security testing is only allowed against a target that is inside an engagement's allowlist, not in its
exclusion list, inside the time window, with a tool the engagement names, and within its request budget.
"""
from __future__ import annotations

import ipaddress
import json
import secrets
import time
from typing import Optional
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator, model_validator

from .store import Store


class Engagement(BaseModel):
    id: str = Field(default_factory=lambda: "eng_" + secrets.token_hex(6))
    name: str
    authorized_by: str = Field(min_length=2)  # person or organisation that owns the targets
    authorization_ref: str = Field(min_length=3)  # signed letter / contract / ticket reference
    targets: list[str] = Field(min_length=1)  # CIDRs, IPs, hostnames, "*.example.com"
    exclusions: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(min_length=1)  # e.g. ["nmap", "zap", "nuclei"]
    starts_at: float = Field(default_factory=time.time)
    ends_at: float
    max_requests: int = Field(1000, ge=1)
    rules_of_engagement: str = ""

    @field_validator("targets", "exclusions")
    @classmethod
    def _valid_targets(cls, v: list[str]) -> list[str]:
        out = []
        for t in v:
            t = t.strip().lower()
            if not t:
                continue
            try:
                net = ipaddress.ip_network(t, strict=False)
                if net.num_addresses > 65536:
                    raise ValueError(f"scope {t} is too broad (max /16 IPv4 equivalent)")
            except ValueError as exc:
                if "too broad" in str(exc):
                    raise
                if t in ("*", "*.*") or t.startswith("*.") and "." not in t[2:]:
                    raise ValueError(f"wildcard scope {t!r} is too broad")
            out.append(t)
        return out

    @model_validator(mode="after")
    def _window(self) -> "Engagement":
        if self.ends_at <= self.starts_at:
            raise ValueError("ends_at must be after starts_at")
        if self.ends_at - self.starts_at > 90 * 86400:
            raise ValueError("an engagement window cannot exceed 90 days")
        return self


def normalize_target(target: str) -> str:
    t = target.strip().lower()
    if "://" in t:
        t = urlsplit(t).hostname or ""
    elif t.count(":") == 1:  # host:port
        t = t.split(":", 1)[0]
    return t.strip("[]").rstrip(".")


def _matches(target: str, pattern: str) -> bool:
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        ip = None
    try:
        net = ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        net = None
    if ip is not None or net is not None:
        if ip is not None and net is not None:
            return ip in net
        if ip is not None and net is None:
            return False
        # target is a hostname, pattern is a network: hostnames must be listed by name
        return False
    if pattern.startswith("*."):
        return target.endswith(pattern[1:]) and target != pattern[2:]
    return target == pattern


class EngagementRegistry:
    def __init__(self, store: Store):
        self.store = store

    def create(self, eng: Engagement) -> Engagement:
        self.store.execute(
            "INSERT INTO engagements(id, data, created) VALUES (?,?,?)", (eng.id, eng.model_dump_json(), time.time())
        )
        self.store.execute("INSERT OR IGNORE INTO engagement_usage(engagement_id) VALUES (?)", (eng.id,))
        return eng

    def get(self, eng_id: str) -> Optional[Engagement]:
        rows = self.store.query("SELECT data, revoked FROM engagements WHERE id=?", (eng_id,))
        if not rows or rows[0]["revoked"]:
            return None
        return Engagement.model_validate_json(rows[0]["data"])

    def list(self) -> list[dict]:
        out = []
        for r in self.store.query(
            "SELECT e.id, e.data, e.revoked, COALESCE(u.requests,0) AS used FROM engagements e "
            "LEFT JOIN engagement_usage u ON u.engagement_id=e.id ORDER BY e.created DESC"
        ):
            d = json.loads(r["data"])
            d.update(revoked=bool(r["revoked"]), requests_used=r["used"])
            out.append(d)
        return out

    def revoke(self, eng_id: str) -> bool:
        return self.store.execute("UPDATE engagements SET revoked=1 WHERE id=?", (eng_id,)).rowcount > 0

    def check(self, eng_id: Optional[str], target: Optional[str], tool: Optional[str]) -> tuple[bool, str]:
        if not eng_id:
            return False, "active security testing needs an engagement_id"
        eng = self.get(eng_id)
        if eng is None:
            return False, "engagement not found or revoked"
        now = time.time()
        if not (eng.starts_at <= now <= eng.ends_at):
            return False, "outside the engagement's authorized time window"
        if not target:
            return False, "a target is required"
        t = normalize_target(target)
        if not t:
            return False, "could not parse target"
        if any(_matches(t, x) for x in eng.exclusions):
            return False, f"target {t} is explicitly excluded"
        if not any(_matches(t, p) for p in eng.targets):
            return False, f"target {t} is not in the engagement allowlist"
        if not tool or tool.lower() not in [x.lower() for x in eng.allowed_tools]:
            return False, f"tool {tool!r} is not authorized for this engagement"
        used = self.store.query("SELECT requests FROM engagement_usage WHERE engagement_id=?", (eng_id,))
        if used and used[0]["requests"] >= eng.max_requests:
            return False, "engagement request budget exhausted"
        return True, "in scope"

    def consume(self, eng_id: str) -> None:
        self.store.execute("UPDATE engagement_usage SET requests = requests + 1 WHERE engagement_id=?", (eng_id,))
