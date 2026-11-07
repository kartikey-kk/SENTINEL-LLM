"""OpenAI-compatible chat completions provider (OpenAI, Azure-compatible gateways,
OpenRouter, Together, Groq, vLLM, LM Studio, Ollama's /v1 endpoint, ...)."""

from __future__ import annotations

import time

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


class OpenAICompatibleProvider(LLMProvider):
    provider_type = "openai_compatible"

    def __init__(
        self,
        *,
        name: str,
        base_url: str,
        api_key: str,
        default_model: str,
        models: list[str],
        timeout: float,
        max_retries: int,
        is_local: bool = False,
    ):
        super().__init__(timeout=timeout, max_retries=max_retries)
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model
        self.configured_models = models
        self.is_local = is_local
        self._has_key = bool(api_key)
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._client = httpx.AsyncClient(
            base_url=self.base_url, headers=headers, timeout=httpx.Timeout(timeout, connect=10.0)
        )

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
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        async def _call() -> dict:
            try:
                resp = await self._client.post("/chat/completions", json=payload)
                resp.raise_for_status()
                return resp.json()
            except Exception as exc:
                raise classify_http_error(exc, self.name) from None

        start = time.perf_counter()
        data, attempts = await self._with_retries(_call)
        latency = (time.perf_counter() - start) * 1000
        text = safe_get(data, "choices", 0, "message", "content", default=None)
        if not isinstance(text, str):
            raise ProviderError(f"{self.name} returned an invalid response", code="provider_invalid_response")
        return LLMResponse(
            text=text,
            provider=self.name,
            model=str(data.get("model") or model_name),
            latency_ms=round(latency, 2),
            prompt_tokens=safe_get(data, "usage", "prompt_tokens"),
            completion_tokens=safe_get(data, "usage", "completion_tokens"),
            finish_reason=safe_get(data, "choices", 0, "finish_reason"),
            attempts=attempts,
        )

    async def list_models(self) -> list[str]:
        if self.configured_models:
            return list(self.configured_models)
        try:
            resp = await self._client.get("/models", timeout=10.0)
            resp.raise_for_status()
            data = resp.json().get("data", [])
            return sorted(m.get("id", "") for m in data if m.get("id"))[:200]
        except Exception as exc:
            raise classify_http_error(exc, self.name) from None

    async def health(self) -> ProviderHealth:
        if not self._has_key and not self.is_local:
            return ProviderHealth(
                provider=self.name,
                provider_type=self.provider_type,
                is_local=self.is_local,
                status="unconfigured",
                detail="Set SENTINEL_CLOUD_API_KEY and SENTINEL_CLOUD_ENABLED=true",
                default_model=self.default_model,
            )
        start = time.perf_counter()
        try:
            resp = await self._client.get("/models", timeout=10.0)
            resp.raise_for_status()
            status = "ok"
            detail = ""
        except Exception as exc:
            err = classify_http_error(exc, self.name)
            status, detail = "unavailable", err.message
        latency = (time.perf_counter() - start) * 1000
        return ProviderHealth(
            provider=self.name,
            provider_type=self.provider_type,
            is_local=self.is_local,
            status=status,  # type: ignore[arg-type]
            latency_ms=round(latency, 2),
            detail=detail,
            models=list(self.configured_models) or [self.default_model],
            default_model=self.default_model,
        )

    async def aclose(self) -> None:
        await self._client.aclose()
