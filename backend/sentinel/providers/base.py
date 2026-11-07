"""Provider-independent LLM interface."""

from __future__ import annotations

import asyncio
import logging
import random
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from typing import Any, Literal, TypeVar

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

T = TypeVar("T")


class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant"]
    content: str


class LLMResponse(BaseModel):
    text: str
    provider: str
    model: str
    latency_ms: float
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    finish_reason: str | None = None
    attempts: int = 1


class ProviderHealth(BaseModel):
    provider: str
    provider_type: str
    is_local: bool
    status: Literal["ok", "degraded", "unavailable", "disabled", "unconfigured"]
    latency_ms: float | None = None
    detail: str = ""
    models: list[str] = Field(default_factory=list)
    default_model: str | None = None


class ProviderError(Exception):
    """Error safe to surface to clients (no credentials, no upstream bodies)."""

    def __init__(self, message: str, *, code: str = "provider_error", retryable: bool = False, status: int = 502):
        super().__init__(message)
        self.message = message
        self.code = code
        self.retryable = retryable
        self.status = status


class LLMProvider(ABC):
    """Base class for all LLM backends."""

    name: str
    provider_type: str
    is_local: bool
    default_model: str

    def __init__(self, *, timeout: float, max_retries: int) -> None:
        self.timeout = timeout
        self.max_retries = max_retries

    @abstractmethod
    async def chat(
        self,
        messages: list[ChatMessage],
        *,
        model: str | None = None,
        temperature: float = 0.2,
        max_tokens: int = 512,
        json_mode: bool = False,
    ) -> LLMResponse:
        """Run a non-streaming chat completion."""

    @abstractmethod
    async def list_models(self) -> list[str]:
        """Return the models this provider can serve."""

    @abstractmethod
    async def health(self) -> ProviderHealth:
        """Check reachability."""

    async def aclose(self) -> None:
        return None

    async def _with_retries(self, fn: Callable[[], Awaitable[T]]) -> tuple[T, int]:
        """Run ``fn`` with bounded exponential backoff for retryable failures."""
        attempt = 0
        while True:
            attempt += 1
            try:
                return await fn(), attempt
            except ProviderError as exc:
                if not exc.retryable or attempt > self.max_retries:
                    raise
                delay = min(8.0, 0.5 * (2 ** (attempt - 1))) + random.uniform(0, 0.25)
                logger.warning("Provider %s retryable error (%s); retry %d in %.2fs", self.name, exc.code, attempt, delay)
                await asyncio.sleep(delay)


def classify_http_error(exc: Exception, provider: str) -> ProviderError:
    """Translate httpx exceptions to safe ProviderErrors."""
    if isinstance(exc, httpx.TimeoutException):
        return ProviderError(f"{provider} request timed out", code="provider_timeout", retryable=True, status=504)
    if isinstance(exc, httpx.ConnectError):
        return ProviderError(f"{provider} is unreachable", code="provider_unreachable", retryable=True, status=503)
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        if code == 401 or code == 403:
            return ProviderError(f"{provider} rejected credentials", code="provider_auth", status=502)
        if code == 404:
            return ProviderError(f"{provider} model or endpoint not found", code="provider_not_found", status=502)
        if code == 429:
            return ProviderError(f"{provider} rate limited the request", code="provider_rate_limited", retryable=True, status=503)
        if code >= 500:
            return ProviderError(f"{provider} upstream error ({code})", code="provider_upstream", retryable=True, status=502)
        return ProviderError(f"{provider} rejected the request ({code})", code="provider_bad_request", status=502)
    if isinstance(exc, httpx.TransportError):
        return ProviderError(f"{provider} transport error", code="provider_transport", retryable=True, status=503)
    return ProviderError(f"{provider} failed unexpectedly", code="provider_error", status=502)


def safe_get(d: Any, *path: Any, default: Any = None) -> Any:
    cur = d
    for p in path:
        try:
            cur = cur[p]
        except (KeyError, IndexError, TypeError):
            return default
    return cur
