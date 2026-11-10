"""Application settings loaded from environment variables / `.env` files.

All secrets come from the environment. Nothing in this module has a usable
default credential: missing admin keys make administrative endpoints fail
closed rather than open.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = BACKEND_DIR.parent

_PLACEHOLDER_SECRETS = {"", "change-me", "change-me-to-a-long-random-string", "change-me-to-another-long-random-string"}


class Settings(BaseSettings):
    """Runtime configuration. Environment variables use the `SENTINEL_` prefix."""

    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_",
        env_file=(str(REPO_ROOT / ".env"), str(BACKEND_DIR / ".env")),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- core ---
    env: str = "development"
    log_level: str = "INFO"
    admin_api_key: SecretStr = SecretStr("")
    require_client_auth: bool = False
    client_api_keys: str = ""
    secret_key: SecretStr = SecretStr("")

    # --- storage ---
    database_url: str = "sqlite+aiosqlite:///./data/sentinel.db"
    redis_url: str = "redis://localhost:6379/0"
    redis_optional: bool = True

    # --- audit ---
    audit_store_redacted_preview: bool = True
    audit_store_raw_prompts: bool = False
    audit_retention_days: int = Field(default=30, ge=1, le=3650)
    audit_fail_closed: bool = True
    audit_preview_chars: int = Field(default=200, ge=0, le=2000)

    # --- limits ---
    max_request_bytes: int = Field(default=65536, ge=1024, le=10_000_000)
    max_input_chars: int = Field(default=20000, ge=100, le=1_000_000)
    rate_limit_per_minute: int = Field(default=120, ge=1)
    detector_timeout_seconds: float = Field(default=20.0, gt=0)
    max_concurrent_inferences: int = Field(default=2, ge=1, le=64)

    # --- ML ---
    ml_enabled: bool = True
    injection_model: str = "protectai/deberta-v3-base-prompt-injection-v2"
    jailbreak_model: str = "jackhhao/jailbreak-classifier"
    toxicity_model: str = "unitary/toxic-bert"
    spacy_model: str = "en_core_web_md"
    ml_device: str = "cpu"
    ml_max_tokens: int = Field(default=512, ge=32, le=4096)

    # --- policy files ---
    policy_file: str = "policies/default.yaml"

    # --- Ollama ---
    ollama_enabled: bool = True
    ollama_base_url: str = "http://localhost:11434"
    ollama_default_model: str = "qwen2.5:3b"

    # --- cloud (OpenAI-compatible) ---
    cloud_enabled: bool = False
    cloud_provider_name: str = "openai_compatible"
    cloud_base_url: str = "https://api.openai.com/v1"
    cloud_api_key: SecretStr = SecretStr("")
    cloud_default_model: str = "gpt-4o-mini"
    cloud_models: str = ""
    cloud_price_input_per_mtok: float = 0.0
    cloud_price_output_per_mtok: float = 0.0

    # --- provider behaviour ---
    provider_timeout_seconds: float = Field(default=120.0, gt=0)
    provider_max_retries: int = Field(default=2, ge=0, le=5)
    allow_cloud_fallback: bool = False

    # --- OpenAI-compatible proxy (/v1) ---
    proxy_enabled: bool = True
    # Callers may send their own provider key (Authorization: Bearer ...); it is forwarded, never stored.
    proxy_allow_byok: bool = True
    # Named upstreams callers can select with X-Sentinel-Upstream. Only these URLs are ever contacted
    # (callers cannot supply a URL, which would turn the proxy into an SSRF relay).
    proxy_upstreams: str = (
        "openai=https://api.openai.com/v1,"
        "groq=https://api.groq.com/openai/v1,"
        "openrouter=https://openrouter.ai/api/v1,"
        "gemini=https://generativelanguage.googleapis.com/v1beta/openai"
    )
    proxy_default_upstream: str = "openai"
    # How a blocked request is returned: "message" = a normal completion with finish_reason
    # "content_filter" (apps keep working); "error" = HTTP 400 in OpenAI's error format.
    proxy_block_mode: Literal["message", "error"] = "message"
    proxy_max_request_bytes: int = Field(default=1_000_000, ge=1024, le=20_000_000)

    # --- CORS (dashboard dev server) ---
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    @field_validator("log_level")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper()

    # ---- derived helpers -------------------------------------------------
    @property
    def is_production(self) -> bool:
        return self.env.lower() == "production"

    @property
    def client_keys(self) -> list[str]:
        return [k.strip() for k in self.client_api_keys.split(",") if k.strip()]

    @property
    def cloud_model_list(self) -> list[str]:
        models = [m.strip() for m in self.cloud_models.split(",") if m.strip()]
        if self.cloud_default_model and self.cloud_default_model not in models:
            models.insert(0, self.cloud_default_model)
        return models

    @property
    def proxy_upstream_map(self) -> dict[str, str]:
        """Parse `name=url,...`. Only https URLs (or http on localhost / Docker host) are accepted."""
        out: dict[str, str] = {}
        for item in self.proxy_upstreams.split(","):
            name, sep, url = item.strip().partition("=")
            name, url = name.strip().lower(), url.strip().rstrip("/")
            if not sep or not name or not url:
                continue
            host = url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
            local = host in ("localhost", "127.0.0.1", "host.docker.internal")
            if url.startswith("https://") or (url.startswith("http://") and local):
                out[name] = url
        return out

    @property
    def admin_key_configured(self) -> bool:
        return self.admin_api_key.get_secret_value() not in _PLACEHOLDER_SECRETS

    @property
    def cloud_configured(self) -> bool:
        return self.cloud_enabled and bool(self.cloud_api_key.get_secret_value()) and bool(self.cloud_base_url)

    def resolve_path(self, value: str) -> Path:
        """Resolve a config path relative to the backend directory."""
        p = Path(value)
        return p if p.is_absolute() else (BACKEND_DIR / p)

    def effective_secret_key(self) -> bytes:
        """Return the secret used for HMAC/encryption.

        In production a real secret is mandatory. In development an ephemeral
        per-process key is generated so nothing falls back to a known constant.
        """
        raw = self.secret_key.get_secret_value()
        if raw in _PLACEHOLDER_SECRETS:
            if self.is_production:
                raise RuntimeError("SENTINEL_SECRET_KEY must be set in production")
            return _ephemeral_key()
        return raw.encode("utf-8")


@lru_cache(maxsize=1)
def _ephemeral_key() -> bytes:
    return os.urandom(32)


def configure_hf_home() -> None:
    """Apply Hugging Face settings (HF_HOME, HF_HUB_OFFLINE) from the environment or `.env`.

    These variables have no SENTINEL_ prefix, so they are read from `.env` here (environment wins).
    HF_HOME is resolved relative to the repository root.
    """
    env_file = REPO_ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            key, sep, value = line.strip().partition("=")
            if sep and key in ("HF_HOME", "HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE") and value and key not in os.environ:
                os.environ[key] = value.strip()
    hf_home = os.environ.get("HF_HOME")
    if hf_home and not Path(hf_home).is_absolute():
        os.environ["HF_HOME"] = str((REPO_ROOT / hf_home).resolve())
    elif hf_home:
        os.environ["HF_HOME"] = hf_home


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
