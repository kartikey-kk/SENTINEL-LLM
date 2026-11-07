"""Shared FastAPI dependencies: app context, authentication, rate limiting."""

from __future__ import annotations

import hmac
import time
from dataclasses import dataclass
from typing import Any

from fastapi import Depends, HTTPException, Request, status

from sentinel.config import Settings


@dataclass
class Caller:
    api_key: str | None
    is_admin: bool
    client_id: str | None


def get_ctx(request: Request) -> Any:
    return request.app.state.ctx


def _extract_key(request: Request) -> str | None:
    key = request.headers.get("x-api-key")
    if key:
        return key.strip()
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def _is_admin(settings: Settings, key: str | None) -> bool:
    if not key or not settings.admin_key_configured:
        return False
    return hmac.compare_digest(key.encode(), settings.admin_api_key.get_secret_value().encode())


async def _rate_limit(request: Request, identity: str) -> None:
    ctx = request.app.state.ctx
    limit = ctx.settings.rate_limit_per_minute
    window = int(time.time() // 60)
    count = await ctx.store.incr_window(f"rl:{identity}:{window}", 61)
    if count > limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(60 - int(time.time()) % 60)},
        )


async def client_caller(request: Request) -> Caller:
    """Auth for inspection/chat endpoints. Admin keys are also accepted."""
    ctx = request.app.state.ctx
    settings: Settings = ctx.settings
    key = _extract_key(request)
    admin = _is_admin(settings, key)
    if settings.require_client_auth and not admin:
        if not key or not any(hmac.compare_digest(key.encode(), k.encode()) for k in settings.client_keys):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Valid API key required",
                                headers={"WWW-Authenticate": "Bearer"})
    client_id = ctx.audit.client_id(key) if key else None
    identity = client_id or f"ip:{request.client.host if request.client else 'unknown'}"
    await _rate_limit(request, identity)
    return Caller(api_key=key, is_admin=admin, client_id=client_id or ("admin" if admin else None))


async def admin_caller(request: Request) -> Caller:
    """Auth for administrative endpoints. Fails closed if no admin key is configured."""
    ctx = request.app.state.ctx
    settings: Settings = ctx.settings
    if not settings.admin_key_configured:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="Administrative access is disabled: SENTINEL_ADMIN_API_KEY is not configured")
    key = _extract_key(request)
    if not _is_admin(settings, key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin API key required",
                            headers={"WWW-Authenticate": "Bearer"})
    await _rate_limit(request, "admin")
    return Caller(api_key=key, is_admin=True, client_id="admin")


ClientDep = Depends(client_caller)
AdminDep = Depends(admin_caller)
