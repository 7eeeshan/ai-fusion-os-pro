"""Model provider that sends a completion to a live local node (the PC running AI Fusion Engine Pro) through the job
queue. If no local node is alive, or it doesn't answer in time, it raises so the Router falls back to the next
provider (e.g. the cloud model). The queued job is then cancelled by its idempotency (it stays unclaimed and fails)."""
from __future__ import annotations

import hashlib
import json
import time

from ..llm import LLMUnavailable


class QueueLLM:
    name = "local-engine-via-queue"

    def __init__(self, queue, timeout_s: float = 120, capability: str = "local-engine"):
        self.q, self.timeout_s, self.cap = queue, timeout_s, capability

    def complete(self, system: str, prompt: str, max_tokens: int = 2000) -> str:
        if not any(n["alive"] and self.cap in n["capabilities"] for n in self.q.nodes()):
            raise LLMUnavailable("no live local node")
        idem = "llm:" + hashlib.sha256(json.dumps([system, prompt, max_tokens, time.time() // 1]).encode()).hexdigest()
        jid, _ = self.q.enqueue("llm.complete", {"system": system, "prompt": prompt, "max_tokens": max_tokens},
                                idem=idem, requires=[self.cap], priority=1, max_attempts=1)
        deadline = time.time() + self.timeout_s
        while time.time() < deadline:
            j = self.q.get(jid)
            if j["status"] == "done":
                return json.loads(j["result"])
            if j["status"] == "failed":
                raise LLMUnavailable(f"local node failed: {j['error'][:200]}")
            time.sleep(0.5)
        raise LLMUnavailable("local node did not answer in time")
