"""Clientes LLM mínimos via HTTP (sem SDK => menos dependências e superfície de ataque).

Todos implementam o protocolo `LLMClient`. Para testes use `StaticLLM`.
"""
from __future__ import annotations

from typing import Protocol

import httpx

from ..config import Settings


class LLMError(RuntimeError):
    pass


class LLMClient(Protocol):
    name: str

    def complete(self, system: str, user: str) -> str: ...


class AnthropicClient:
    """Anthropic Messages API (POST /v1/messages)."""
    name = "anthropic"

    def __init__(self, api_key: str, model: str, timeout: float, base_url: str | None = None):
        self._url = (base_url or "https://api.anthropic.com").rstrip("/") + "/v1/messages"
        self._headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
        self._model, self._timeout = model, timeout

    def complete(self, system: str, user: str) -> str:
        body = {"model": self._model, "max_tokens": 1024, "temperature": 0, "system": system,
                "messages": [{"role": "user", "content": user}]}
        try:
            r = httpx.post(self._url, headers=self._headers, json=body, timeout=self._timeout)
            r.raise_for_status()
            data = r.json()
            return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            raise LLMError(f"falha na chamada Anthropic: {type(exc).__name__}") from exc


class OpenAICompatibleClient:
    """Qualquer endpoint compatível com /v1/chat/completions (OpenAI, Ollama, vLLM...)."""
    name = "openai"

    def __init__(self, api_key: str, model: str, timeout: float, base_url: str | None = None):
        self._url = (base_url or "https://api.openai.com").rstrip("/") + "/v1/chat/completions"
        self._headers = {"Authorization": f"Bearer {api_key}", "content-type": "application/json"}
        self._model, self._timeout = model, timeout

    def complete(self, system: str, user: str) -> str:
        body = {"model": self._model, "temperature": 0,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        try:
            r = httpx.post(self._url, headers=self._headers, json=body, timeout=self._timeout)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        except (httpx.HTTPError, ValueError, KeyError, IndexError) as exc:
            raise LLMError(f"falha na chamada OpenAI-compatível: {type(exc).__name__}") from exc


class StaticLLM:
    """Stub determinístico para testes/demos offline."""
    name = "static"

    def __init__(self, response: str | Exception):
        self.response = response
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def build_client(s: Settings) -> LLMClient | None:
    if not s.llm_enabled:
        return None
    key = s.llm_api_key.get_secret_value()  # type: ignore[union-attr]
    cls = AnthropicClient if s.llm_provider == "anthropic" else OpenAICompatibleClient
    return cls(key, s.llm_model, s.llm_timeout_seconds, s.llm_base_url)  # type: ignore[arg-type]
