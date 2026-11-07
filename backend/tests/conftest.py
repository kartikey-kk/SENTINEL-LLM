"""Shared fixtures.

* ``make_settings`` builds isolated settings (temp SQLite, in-process KV store,
  no real LLM providers).
* ``client`` starts the full app without ML models (fast; PII uses the regex
  fallback). ``ml_client`` loads the real classifiers + Presidio once per session.
* ``FakeProvider`` replaces LLM backends and records exactly what was sent, so
  tests can assert what would have left the machine.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from sentinel.config import Settings  # noqa: E402
from sentinel.main import create_app  # noqa: E402
from sentinel.providers.base import ChatMessage, LLMProvider, LLMResponse, ProviderHealth  # noqa: E402

ADMIN_KEY = "test-admin-key-0123456789abcdef"
ADMIN = {"X-API-Key": ADMIN_KEY}


def make_settings(tmp_path: Path, **overrides) -> Settings:
    base = dict(
        _env_file=None,
        env="test",
        admin_api_key=ADMIN_KEY,
        secret_key="test-secret-key-0123456789abcdef0123",
        database_url=f"sqlite+aiosqlite:///{(tmp_path / 'test.db').as_posix()}",
        redis_url="redis://127.0.0.1:1/0",
        redis_optional=True,
        ollama_enabled=False,
        cloud_enabled=False,
        rate_limit_per_minute=10_000,
        cors_origins="",
        audit_fail_closed=True,
    )
    base.update(overrides)
    return Settings(**base)


class FakeProvider(LLMProvider):
    provider_type = "fake"

    def __init__(self, name: str, is_local: bool, reply: Callable[[list[ChatMessage]], str] | str = "Hello from fake LLM."):
        super().__init__(timeout=5, max_retries=0)
        self.name = name
        self.is_local = is_local
        self.default_model = "fake-model"
        self.reply = reply
        self.calls: list[list[ChatMessage]] = []

    async def chat(self, messages, *, model=None, temperature=0.2, max_tokens=512, json_mode=False) -> LLMResponse:
        self.calls.append(list(messages))
        text = self.reply(messages) if callable(self.reply) else self.reply
        return LLMResponse(text=text, provider=self.name, model=model or self.default_model, latency_ms=1.0,
                           prompt_tokens=sum(len(m.content) for m in messages) // 4, completion_tokens=len(text) // 4)

    async def list_models(self) -> list[str]:
        return [self.default_model]

    async def health(self) -> ProviderHealth:
        return ProviderHealth(provider=self.name, provider_type="fake", is_local=self.is_local, status="ok",
                              models=[self.default_model], default_model=self.default_model)

    def sent_text(self) -> str:
        return "\n".join(m.content for call in self.calls for m in call)


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    app = create_app(make_settings(tmp_path, ml_enabled=False), load_models=False)
    with TestClient(app) as c:
        ctx = app.state.ctx
        ctx.router.providers["ollama"] = FakeProvider("ollama", True)
        ctx.router.providers["openai_compatible"] = FakeProvider("openai_compatible", False)
        yield c


def _models_available() -> bool:
    from sentinel.config import configure_hf_home

    configure_hf_home()
    hf = Path(os.environ.get("HF_HOME", ""))
    return hf.exists() and any(hf.rglob("config.json"))


@pytest.fixture(scope="session")
def ml_app(tmp_path_factory: pytest.TempPathFactory):
    if not _models_available():
        pytest.skip("ML models not downloaded (run scripts/download_models.py)")
    tmp = tmp_path_factory.mktemp("ml")
    app = create_app(make_settings(tmp, ml_enabled=True), load_models=True)
    with TestClient(app) as c:
        ctx = app.state.ctx
        ctx.router.providers["ollama"] = FakeProvider("ollama", True)
        ctx.router.providers["openai_compatible"] = FakeProvider("openai_compatible", False)
        yield app, c


@pytest.fixture
def ml_client(ml_app) -> TestClient:
    return ml_app[1]
