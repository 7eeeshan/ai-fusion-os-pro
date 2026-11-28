"""Optional link to AI Fusion Engine Pro (its local API, default http://127.0.0.1:8765).

AI Fusion OS Pro runs on its own. When the engine is configured and reachable, model calls go to it; otherwise the
link reports itself unavailable and nothing pretends otherwise.
"""
from __future__ import annotations

import os
from typing import Any, Optional

import httpx


class EngineUnavailable(RuntimeError):
    pass


class EngineLink:
    def __init__(self, base_url: Optional[str] = None, token: Optional[str] = None,
                 client: Optional[httpx.Client] = None, timeout: float = 120):
        self.base_url = (base_url or os.environ.get("AFE_URL", "http://127.0.0.1:8765")).rstrip("/")
        self.token = token if token is not None else os.environ.get("AFE_TOKEN", "")
        # The bundled engine writes its token on first start, which can be after this link was made.
        self._lookup = token is None and not self.token
        self.client = client or httpx.Client(timeout=timeout)

    def _headers(self) -> dict[str, str]:
        if not self.token and self._lookup:
            from .desktop import find_engine_token
            self.token = find_engine_token(dict(os.environ)) or ""
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def status(self) -> dict[str, Any]:
        try:
            r = self.client.get(f"{self.base_url}/health", timeout=3)
            r.raise_for_status()
            self._headers()
            return {"connected": True, "url": self.base_url, "health": r.json(), "token_set": bool(self.token)}
        except (httpx.HTTPError, ValueError) as exc:
            return {"connected": False, "url": self.base_url, "error": str(exc)[:200], "token_set": bool(self.token)}

    def models(self) -> list[dict]:
        try:
            r = self.client.get(f"{self.base_url}/v1/models", headers=self._headers())
            r.raise_for_status()
        except httpx.HTTPError as exc:
            raise EngineUnavailable(str(exc)) from exc
        return r.json().get("data", [])

    def chat(self, model: str, messages: list[dict], **kw: Any) -> str:
        body = {"model": model, "messages": messages, "stream": False, **kw}
        try:
            r = self.client.post(f"{self.base_url}/v1/chat/completions", json=body, headers=self._headers())
            r.raise_for_status()
        except httpx.HTTPError as exc:
            raise EngineUnavailable(str(exc)) from exc
        return r.json()["choices"][0]["message"]["content"]
