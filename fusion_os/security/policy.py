"""Policy engine.

Two layers:
1. IMMUTABLE_RULES live in code. A policy file cannot weaken them, and ordinary agents cannot change code at runtime.
2. The policy file (JSON) is pinned by SHA-256 in a lock file next to it. If the file changes without the lock being
   updated through the admin path, the controller fails closed: every request is denied until an admin re-installs it.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator

Effect = Literal["allow", "deny", "require_approval"]
ZONES = ("standard", "research", "darkweb", "security")


class ActionRequest(BaseModel):
    agent_id: str
    action: str = Field(pattern=r"^[a-z][a-z0-9_.]*$")
    zone: str = "standard"
    mission_id: Optional[str] = None
    engagement_id: Optional[str] = None
    target: Optional[str] = None
    params: dict[str, Any] = Field(default_factory=dict)
    est_calls: int = Field(1, ge=0)
    est_seconds: float = Field(0, ge=0)
    est_usd: float = Field(0, ge=0)
    approval_id: Optional[str] = None
    justification: str = ""

    @field_validator("zone")
    @classmethod
    def _zone(cls, v: str) -> str:
        if v not in ZONES:
            raise ValueError(f"zone must be one of {ZONES}")
        return v

    def fingerprint(self) -> str:
        """Hash of what is being approved. approval_id/justification are excluded so a resubmission matches."""
        body = self.model_dump(exclude={"approval_id", "justification"})
        return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


class Rule(BaseModel):
    id: str
    actions: list[str]
    effect: Effect
    zones: Optional[list[str]] = None
    when: dict[str, list[Any]] = Field(default_factory=dict)
    requires_engagement: bool = False

    def matches(self, req: ActionRequest) -> bool:
        if not any(fnmatch.fnmatchcase(req.action, a) for a in self.actions):
            return False
        if self.zones is not None and req.zone not in self.zones:
            return False
        for key, allowed in self.when.items():
            if req.params.get(key) not in allowed:
                return False
        return True


class PolicyDoc(BaseModel):
    version: int
    description: str = ""
    approval_ttl_seconds: int = Field(86400, ge=60, le=30 * 86400)
    rules: list[Rule]


# Checked before the policy file; a policy file cannot override these.
IMMUTABLE_RULES: list[Rule] = [
    Rule(id="immutable:no-policy-change", actions=["policy.*", "security.controller.*"], effect="deny"),
    # Dark-web zone is isolated from credentials, private files, privileged tools and skill/system changes.
    Rule(id="immutable:darkweb-isolation", zones=["darkweb"], effect="deny",
         actions=["credential.*", "files.*", "security.*", "skill.register", "system.*", "model.install",
                  "agent.spawn", "sandbox.exec", "memory.write", "research.web.*", "research.deep.*"]),
    # Tor is only reachable from the dark-web zone.
    Rule(id="immutable:tor-only-in-darkweb", zones=["standard", "research", "security"], actions=["research.tor.*"],
         effect="deny"),
    # Unlawful activity is never allowed, by any rule.
    Rule(id="immutable:prohibited", effect="deny",
         actions=["*.purchase", "*.transaction", "credential.harvest", "credential.steal", "*.phish", "*.ddos",
                  "malware.build", "malware.deploy", "*.unauthorized_access"]),
]


@dataclass
class Decision:
    effect: Effect
    rule_id: str
    reason: str
    requires_engagement: bool = False
    extra: dict = field(default_factory=dict)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def default_policy_text() -> str:
    return resources.files("fusion_os.security").joinpath("default_policy.json").read_text(encoding="utf-8")


# SHA-256 of earlier *unmodified* default policies. An untouched old default is upgraded to the current default on
# start; a policy the admin changed is never replaced automatically.
PREVIOUS_DEFAULTS = {"fdf59e84b73708797c135b78a64f721ccab8aab28cbba4c7be75a37a99e33852",
                     "a208e3cbe5b6e411ff75e2e746e0196f724b8cfb9d58f2b98ea655ad04c9db9e",
                     "6a98b87a1dd7864f24bbeb6de6c19d6ce80d9d15f871867a98728765f86bb171"}


class PolicyEngine:
    def __init__(self, policy_file: Path, lock_file: Path):
        self.policy_file = policy_file
        self.lock_file = lock_file
        self.doc: Optional[PolicyDoc] = None
        self.integrity_error: Optional[str] = None
        if not policy_file.exists():
            self.install(default_policy_text())
        self.upgraded_from: Optional[str] = None
        cur = self.current_hash()
        try:
            pinned = lock_file.read_text(encoding="utf-8").strip()
        except OSError:
            pinned = ""
        if cur in PREVIOUS_DEFAULTS and cur == pinned:
            self.upgraded_from = cur
            self.install(default_policy_text())
        self.reload()

    def install(self, text: str) -> str:
        """Admin path only (the controller exposes this behind the admin token)."""
        doc = PolicyDoc.model_validate_json(text)  # validate before writing
        from ..paths import write_private
        write_private(self.policy_file, text)
        write_private(self.lock_file, sha256_text(text))
        self.reload()
        return f"policy v{doc.version} installed"

    def reload(self) -> None:
        try:
            text = self.policy_file.read_text(encoding="utf-8")
            pinned = self.lock_file.read_text(encoding="utf-8").strip()
            if sha256_text(text) != pinned:
                raise ValueError("policy file hash does not match its lock: file was changed outside the admin path")
            self.doc = PolicyDoc.model_validate_json(text)
            self.integrity_error = None
        except Exception as exc:  # fail closed
            self.doc = None
            self.integrity_error = str(exc)

    def current_hash(self) -> Optional[str]:
        try:
            return sha256_text(self.policy_file.read_text(encoding="utf-8"))
        except OSError:
            return None

    def verify(self) -> bool:
        """Re-check the pinned hash; on mismatch the engine fails closed."""
        try:
            pinned = self.lock_file.read_text(encoding="utf-8").strip()
        except OSError:
            pinned = ""
        if self.doc is not None and self.current_hash() != pinned:
            self.reload()
        return self.doc is not None

    def evaluate(self, req: ActionRequest) -> Decision:
        # Detect tampering on every decision, not only at start-up.
        self.verify()
        if self.doc is None:
            return Decision("deny", "integrity", f"policy integrity failure, failing closed: {self.integrity_error}")
        for rule in IMMUTABLE_RULES:
            if rule.matches(req):
                return Decision("deny", rule.id, "blocked by immutable security rule")
        for rule in self.doc.rules:
            if rule.matches(req):
                return Decision(rule.effect, rule.id, f"matched rule '{rule.id}'", rule.requires_engagement)
        return Decision("deny", "default", "no rule allows this action (default deny)")
