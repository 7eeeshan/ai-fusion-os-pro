"""Model access with fallback: AI Fusion Engine Pro (local) and Anthropic (cloud), tried in a configured order.

Order comes from FUSION_OS_LLM_ORDER (default "engine,anthropic"). A provider that isn't configured or fails is
skipped and the next one is used; if none works, LLMUnavailable is raised. Nothing is simulated.
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Optional, Protocol

import httpx

from .engine_link import EngineLink, EngineUnavailable


class LLMUnavailable(RuntimeError):
    pass


class LLM(Protocol):
    name: str

    def complete(self, system: str, prompt: str, max_tokens: int = 2000) -> str: ...


class EngineLLM:
    name = "engine"

    def __init__(self, link: Optional[EngineLink] = None, model: Optional[str] = None):
        self.link = link or EngineLink()
        self.model = model or os.environ.get("FUSION_OS_ENGINE_MODEL", "")

    def complete(self, system: str, prompt: str, max_tokens: int = 2000) -> str:
        model = self.model
        if not model:
            models = self.link.models()
            if not models:
                raise EngineUnavailable("engine has no models loaded")
            model = models[0]["id"]
        return self.link.chat(model, [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
                              max_tokens=max_tokens)

    def chat(self, system: str, messages: list[dict], max_tokens: int = 2000) -> str:
        model = self.model
        if not model:
            models = self.link.models()
            if not models:
                raise EngineUnavailable("engine has no models loaded")
            model = models[0]["id"]
        return self.link.chat(model, [{"role": "system", "content": system}, *messages], max_tokens=max_tokens)


class AnthropicLLM:
    name = "anthropic"

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None, client: Optional[httpx.Client] = None):
        self.api_key = api_key if api_key is not None else os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model or os.environ.get("FUSION_OS_ANTHROPIC_MODEL", "claude-sonnet-5-5")
        self.client = client or httpx.Client(timeout=180)

    def complete(self, system: str, prompt: str, max_tokens: int = 2000) -> str:
        if not self.api_key:
            raise LLMUnavailable("ANTHROPIC_API_KEY not set")
        r = self.client.post("https://api.anthropic.com/v1/messages", headers={
            "x-api-key": self.api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": self.model, "max_tokens": max_tokens, "system": system,
                  "messages": [{"role": "user", "content": prompt}]})
        r.raise_for_status()
        return "".join(b.get("text", "") for b in r.json().get("content", []) if b.get("type") == "text")

    def chat(self, system: str, messages: list[dict], max_tokens: int = 2000) -> str:
        if not self.api_key:
            raise LLMUnavailable("ANTHROPIC_API_KEY not set")
        r = self.client.post("https://api.anthropic.com/v1/messages", headers={
            "x-api-key": self.api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": self.model, "max_tokens": max_tokens, "system": system, "messages": messages})
        r.raise_for_status()
        return "".join(b.get("text", "") for b in r.json().get("content", []) if b.get("type") == "text")


class Router:
    """Tries providers in order; records which one answered and how long it took."""

    def __init__(self, providers: Optional[list[Any]] = None):
        if providers is None:
            order = os.environ.get("FUSION_OS_LLM_ORDER", "engine,anthropic").split(",")
            table = {"engine": EngineLLM, "anthropic": AnthropicLLM}
            providers = [table[p.strip()]() for p in order if p.strip() in table]
        self.providers = providers
        self.last: dict[str, Any] = {}
        self.name = "router"

    def complete(self, system: str, prompt: str, max_tokens: int = 2000) -> str:
        errors = []
        for p in self.providers:
            t0 = time.monotonic()
            try:
                out = p.complete(system, prompt, max_tokens)
                self.last = {"provider": p.name, "seconds": time.monotonic() - t0, "fallbacks": errors}
                return out
            except Exception as exc:  # any provider failure -> next provider
                errors.append(f"{p.name}: {str(exc)[:200]}")
        raise LLMUnavailable("no model provider available: " + "; ".join(errors))

    def chat(self, system: str, messages: list[dict], max_tokens: int = 2000) -> str:
        """Multi-turn chat. `messages` alternate user/assistant and end with a user turn. Providers without a chat
        method get the conversation as one transcript."""
        errors = []
        for p in self.providers:
            t0 = time.monotonic()
            try:
                if hasattr(p, "chat"):
                    out = p.chat(system, messages, max_tokens)
                else:
                    out = p.complete(system, transcript(messages), max_tokens)
                self.last = {"provider": p.name, "seconds": time.monotonic() - t0, "fallbacks": errors}
                return out
            except Exception as exc:
                errors.append(f"{p.name}: {str(exc)[:200]}")
        raise LLMUnavailable("no model provider available: " + "; ".join(errors))


def transcript(messages: list[dict]) -> str:
    lines = [f"{'User' if m['role'] == 'user' else 'Assistant'}: {m['content']}" for m in messages]
    return "\n\n".join(lines) + "\n\nAssistant:"


def extract_json(text: str) -> Any:
    """Parse the first JSON object/array in a model reply (models often wrap JSON in prose or code fences)."""
    m = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if m:
        text = m.group(1)
    for opener, closer in (("{", "}"), ("[", "]")):
        s = text.find(opener)
        e = text.rfind(closer)
        if s != -1 and e > s:
            try:
                return json.loads(text[s:e + 1])
            except ValueError:
                continue
    raise ValueError("no JSON found in model output")
