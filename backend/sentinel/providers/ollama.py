"""Ollama local inference provider."""

from __future__ import annotations

import time
from typing import Literal

import httpx

from sentinel.providers.base import (
    ChatMessage,
    LLMProvider,
    LLMResponse,
    ProviderError,
    ProviderHealth,
    classify_http_error,
    safe_get,
)


class OllamaProvider(LLMProvider):
    provider_type = "ollama"
    is_local = True

    def __init__(self, *, base_url: str, default_model: str, timeout: float, max_retries: int, name: str = "ollama"):
        super().__init__(timeout=timeout, max_retries=max_retries)
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=httpx.Timeout(timeout, connect=5.0))

    async def chat(
        self,
        messages: list[ChatMessage],
        *,
        model: str | None = None,
        temperature: float = 0.2,
        max_tokens: int = 512,
        json_mode: bool = False,
    ) -> LLMResponse:
        model_name = model or self.default_model
        payload: dict = {
            "model": model_name,
            "messages": [m.model_dump() for m in messages],
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        if json_mode:
            payload["format"] = "json"

        async def _call() -> dict:
            try:
                resp = await self._client.post("/api/chat", json=payload)
                resp.raise_for_status()
                return resp.json()
            except Exception as exc:  # translated to a safe error
                raise classify_http_error(exc, self.name) from None

        start = time.perf_counter()
        data, attempts = await self._with_retries(_call)
        latency = (time.perf_counter() - start) * 1000
        text = safe_get(data, "message", "content", default=None)
        if not isinstance(text, str):
            raise ProviderError(f"{self.name} returned an invalid response", code="provider_invalid_response")
        return LLMResponse(
            text=text,
            provider=self.name,
            model=model_name,
            latency_ms=round(latency, 2),
            prompt_tokens=data.get("prompt_eval_count"),
            completion_tokens=data.get("eval_count"),
            finish_reason=data.get("done_reason"),
            attempts=attempts,
        )

    async def list_models(self) -> list[str]:
        try:
            resp = await self._client.get("/api/tags", timeout=5.0)
            resp.raise_for_status()
            return sorted(m.get("name", "") for m in resp.json().get("models", []) if m.get("name"))
        except Exception as exc:
            raise classify_http_error(exc, self.name) from None

    async def health(self) -> ProviderHealth:
        start = time.perf_counter()
        try:
            models = await self.list_models()
        except ProviderError as exc:
            return ProviderHealth(
                provider=self.name,
                provider_type=self.provider_type,
                is_local=True,
                status="unavailable",
                detail=f"{exc.message}. Install Ollama from https://ollama.com and run `ollama serve`.",
                default_model=self.default_model,
            )
        latency = (time.perf_counter() - start) * 1000
        has_default = any(m == self.default_model or m.split(":")[0] == self.default_model for m in models)
        status: Literal["ok", "degraded"] = "ok" if has_default else "degraded"
        detail = "" if has_default else f"Default model not installed. Run: ollama pull {self.default_model}"
        return ProviderHealth(
            provider=self.name,
            provider_type=self.provider_type,
            is_local=True,
            status=status,
            latency_ms=round(latency, 2),
            detail=detail,
            models=models,
            default_model=self.default_model,
        )

    async def aclose(self) -> None:
        await self._client.aclose()
