"""FastAPI application factory and lifespan wiring.

Run locally:  uvicorn sentinel.main:app --host 127.0.0.1 --port 8000   (from backend/)
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from sentinel import __version__
from sentinel.api.middleware import RequestContextMiddleware, install_error_handlers
from sentinel.api.routes import admin, inspect, system
from sentinel.audit.service import AuditService
from sentinel.config import Settings, configure_hf_home, get_settings
from sentinel.db.models import ModelProvider
from sentinel.db.session import Database, build_database
from sentinel.detection.classifiers import ModelRegistry, build_registry
from sentinel.detection.context_detector import ContextSecurityDetector
from sentinel.detection.injection_detector import PromptInjectionDetector
from sentinel.detection.jailbreak_detector import JailbreakDetector
from sentinel.detection.output_validator import OutputValidator
from sentinel.detection.pii_detector import PIIDetector
from sentinel.detection.secret_detector import SecretDetector
from sentinel.detection.toxicity_detector import ToxicityDetector
from sentinel.detection.verifier import LLMVerifier
from sentinel.engine.pipeline import SentinelPipeline
from sentinel.engine.policy_engine import PolicyStore
from sentinel.providers.router import ProviderRouter
from sentinel.security.kv_store import KVStore, build_store
from sentinel.security.pii_vault import PIIVault
from sentinel.security.tool_guard import ToolGuard

logger = logging.getLogger("sentinel")


@dataclass
class AppContext:
    settings: Settings
    db: Database
    store: KVStore
    registry: ModelRegistry
    pii: PIIDetector
    policy_store: PolicyStore
    router: ProviderRouter
    tool_guard: ToolGuard
    audit: AuditService
    pipeline: SentinelPipeline


async def build_context(settings: Settings, *, load_models: bool = True) -> AppContext:
    configure_hf_home()
    db = build_database(settings)
    await db.create_all()
    store = await build_store(settings.redis_url, settings.redis_optional)

    policy_store = PolicyStore.from_file(settings.resolve_path(settings.policy_file))
    async with db.sessionmaker() as s:
        applied = await policy_store.load_overrides(s)
        if applied:
            logger.info("Applied %d stored policy section overrides (version %d)", applied, policy_store.current.version)

    registry = build_registry(settings)
    pii = PIIDetector(settings.spacy_model)
    if load_models:
        # Models load exactly once, off the event loop.
        await asyncio.to_thread(registry.load_all)
        await asyncio.to_thread(pii.load)
    else:
        logger.warning("Model loading skipped; PII uses regex fallback and ML detectors are unavailable")

    secret = SecretDetector()
    injection = PromptInjectionDetector(registry)
    jailbreak = JailbreakDetector(registry)
    toxicity = ToxicityDetector(registry)
    router = ProviderRouter.from_settings(settings)
    audit = AuditService(db, settings)
    tool_guard = ToolGuard(store, settings.effective_secret_key())
    pipeline = SentinelPipeline(
        settings=settings, injection=injection, jailbreak=jailbreak, pii=pii, secret=secret, toxicity=toxicity,
        context=ContextSecurityDetector(registry, pii, secret),
        output_validator=OutputValidator(pii, secret, toxicity, injection),
        verifier=LLMVerifier(router), router=router, policy_store=policy_store, tool_guard=tool_guard,
        vault=PIIVault(store, settings.effective_secret_key()), audit=audit,
    )
    await _sync_providers(db, router, settings)
    return AppContext(settings=settings, db=db, store=store, registry=registry, pii=pii, policy_store=policy_store,
                      router=router, tool_guard=tool_guard, audit=audit, pipeline=pipeline)


async def _sync_providers(db: Database, router: ProviderRouter, settings: Settings) -> None:
    """Mirror configured providers into model_providers (no credentials - only the env var name)."""
    async with db.sessionmaker() as s:
        existing = {p.name: p for p in (await s.execute(select(ModelProvider))).scalars().all()}
        for name, prov in router.providers.items():
            row = existing.get(name) or ModelProvider(name=name)
            row.provider_type = prov.provider_type
            row.base_url = getattr(prov, "base_url", "")
            row.default_model = prov.default_model
            row.is_local = prov.is_local
            row.enabled = True
            row.api_key_env = None if prov.is_local else "SENTINEL_CLOUD_API_KEY"
            s.add(row)
        for name, row in existing.items():
            if name not in router.providers:
                row.enabled = False
        await s.commit()


async def _retention_loop(ctx: AppContext) -> None:
    await asyncio.sleep(30)  # do not compete with startup / first requests
    while True:
        try:
            purged = await ctx.audit.purge_expired()
            if purged:
                logger.info("Retention purge removed %d events", purged)
        except Exception as exc:  # keep the loop alive
            logger.warning("Retention purge failed: %s", type(exc).__name__)
        await asyncio.sleep(6 * 3600)


def create_app(settings: Settings | None = None, *, load_models: bool = True) -> FastAPI:
    settings = settings or get_settings()
    logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> Any:
        if not settings.admin_key_configured:
            logger.warning("SENTINEL_ADMIN_API_KEY is not set: administrative endpoints are disabled (fail closed)")
        ctx = await build_context(settings, load_models=load_models)
        app.state.ctx = ctx
        task = asyncio.create_task(_retention_loop(ctx))
        logger.info("SentinelLLM %s ready (providers: %s)", __version__, ", ".join(ctx.router.providers) or "none")
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task  # let in-flight DB work unwind before disposing the engine
            await ctx.router.aclose()
            await ctx.store.close()
            await ctx.db.dispose()

    app = FastAPI(
        title="SentinelLLM",
        version=__version__,
        description="Unified LLM firewall and security gateway. Admin endpoints require `X-API-Key`.",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )
    origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
    if origins:
        app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST", "PUT"],
                           allow_headers=["Content-Type", "X-API-Key", "Authorization"], expose_headers=["X-Request-ID"])
    app.add_middleware(RequestContextMiddleware, max_body_bytes=settings.max_request_bytes)
    install_error_handlers(app)
    app.include_router(system.router)
    app.include_router(inspect.router)
    app.include_router(admin.router)
    return app


app = create_app()
