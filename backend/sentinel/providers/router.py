"""Module I - LLM provider router.

Providers are configured from environment variables only. There is no silent
fallback from local to cloud inference: a fallback provider is returned only
when *both* ``SENTINEL_ALLOW_CLOUD_FALLBACK=true`` and the policy's
``providers.allow_cloud_fallback`` are set, and the pipeline re-applies the
cloud privacy policy (PII redaction, secret blocking) before using it.
"""

from __future__ import annotations

import asyncio

from sentinel.config import Settings
from sentinel.providers.base import LLMProvider, ProviderError, ProviderHealth
from sentinel.providers.ollama import OllamaProvider
from sentinel.providers.openai_compat import OpenAICompatibleProvider


class ProviderRouter:
    def __init__(self, providers: dict[str, LLMProvider], *, allow_cloud_fallback: bool = False) -> None:
        self.providers = providers
        self.allow_cloud_fallback_env = allow_cloud_fallback

    @classmethod
    def from_settings(cls, settings: Settings) -> "ProviderRouter":
        providers: dict[str, LLMProvider] = {}
        if settings.ollama_enabled:
            providers["ollama"] = OllamaProvider(
                base_url=settings.ollama_base_url,
                default_model=settings.ollama_default_model,
                timeout=settings.provider_timeout_seconds,
                max_retries=settings.provider_max_retries,
            )
        if settings.cloud_enabled:
            providers[settings.cloud_provider_name] = OpenAICompatibleProvider(
                name=settings.cloud_provider_name,
                base_url=settings.cloud_base_url,
                api_key=settings.cloud_api_key.get_secret_value(),
                default_model=settings.cloud_default_model,
                models=settings.cloud_model_list,
                timeout=settings.provider_timeout_seconds,
                max_retries=settings.provider_max_retries,
                is_local=False,
            )
        return cls(providers, allow_cloud_fallback=settings.allow_cloud_fallback)

    @property
    def default_name(self) -> str | None:
        if "ollama" in self.providers:
            return "ollama"
        return next(iter(self.providers), None)

    def get(self, name: str | None) -> LLMProvider:
        key = name or self.default_name
        if key is None or key not in self.providers:
            raise ProviderError(
                f"Provider '{name}' is not configured", code="provider_not_configured", status=400
            )
        return self.providers[key]

    def fallback_for(self, provider: LLMProvider, policy_allows: bool) -> LLMProvider | None:
        """Return a cloud fallback only when explicitly enabled in BOTH env and policy."""
        if not (self.allow_cloud_fallback_env and policy_allows) or not provider.is_local:
            return None
        return next((p for p in self.providers.values() if not p.is_local), None)

    async def health_all(self) -> list[ProviderHealth]:
        return list(await asyncio.gather(*(p.health() for p in self.providers.values())))

    async def aclose(self) -> None:
        await asyncio.gather(*(p.aclose() for p in self.providers.values()), return_exceptions=True)
