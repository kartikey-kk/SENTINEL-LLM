"""Health and model/provider status endpoints."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Request
from sqlalchemy import func, select

from sentinel import __version__
from sentinel.api.deps import Caller, ClientDep, get_ctx
from sentinel.db.models import RequestMetric

router = APIRouter(prefix="/api/v1", tags=["system"])


@router.get("/health", summary="Liveness and component health")
async def health(request: Request) -> dict:
    ctx = get_ctx(request)
    db_ok, kv_ok = await asyncio.gather(ctx.db.ping(), ctx.store.ping())
    classifiers = {s.name: s.available for s in ctx.registry.statuses()}
    critical_ok = db_ok and kv_ok
    degraded = (not all(classifiers.values())) if classifiers else ctx.settings.ml_enabled
    return {
        "status": "ok" if critical_ok and not degraded else ("degraded" if critical_ok else "unavailable"),
        "version": __version__,
        "components": {
            "database": "ok" if db_ok else "unavailable",
            "kv_store": {"backend": ctx.store.backend, "status": "ok" if kv_ok else "unavailable"},
            "classifiers": classifiers,
            "pii_engine": ctx.pii.engine_name,
            "policy_version": ctx.policy_store.current.version,
            "admin_auth": "configured" if ctx.settings.admin_key_configured else "NOT CONFIGURED (admin endpoints disabled)",
        },
    }


@router.get("/models", summary="Local/cloud LLM providers, classifiers and observed latency")
async def models(request: Request, caller: Caller = ClientDep) -> dict:
    ctx = get_ctx(request)
    providers = await ctx.router.health_all()
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    async with ctx.db.sessionmaker() as s:
        rows = (await s.execute(
            select(RequestMetric.provider, RequestMetric.model, func.count(RequestMetric.id),
                   func.avg(RequestMetric.llm_latency_ms))
            .where(RequestMetric.timestamp >= since, RequestMetric.llm_latency_ms.is_not(None))
            .group_by(RequestMetric.provider, RequestMetric.model)
        )).all()
    latency = [{"provider": p, "model": m, "calls": n, "avg_latency_ms": round(a, 2) if a is not None else None}
               for p, m, n, a in rows]
    vp = ctx.policy_store.current.verification
    verifier_provider = next((p for p in providers if p.provider == vp.provider), None)
    verifier_model = vp.model or (verifier_provider.default_model if verifier_provider else None)
    installed = None
    if verifier_provider is not None and verifier_provider.provider_type == "ollama":
        installed = verifier_model in verifier_provider.models
    verifier = {
        **vp.model_dump(), "resolved_model": verifier_model, "provider_status": verifier_provider.status if verifier_provider else "not_configured",
        "model_installed": installed,
        "install_hint": f"ollama pull {verifier_model}" if installed is False else None,
    }
    return {
        "providers": [p.model_dump() for p in providers],
        "cloud": {
            "enabled": ctx.settings.cloud_enabled,
            "configured": ctx.settings.cloud_configured,
            "base_url_host": _host(ctx.settings.cloud_base_url) if ctx.settings.cloud_enabled else None,
            "api_key_present": bool(ctx.settings.cloud_api_key.get_secret_value()),  # boolean only, never the key
            "fallback_enabled_env": ctx.settings.allow_cloud_fallback,
            "fallback_enabled_policy": ctx.policy_store.current.providers.allow_cloud_fallback,
        },
        "classifiers": [s.__dict__ for s in ctx.registry.statuses()],
        "pii": ctx.pii.status(),
        "observed_latency_24h": latency,
        "verification": verifier,
    }


def _host(url: str) -> str:
    from urllib.parse import urlparse

    return urlparse(url).netloc
