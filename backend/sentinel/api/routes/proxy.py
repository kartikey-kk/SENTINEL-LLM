"""OpenAI-compatible endpoints: point any OpenAI client's `base_url` at `<sentinel>/v1`.

Headers:
  Authorization: Bearer <provider key>  - the caller's own OpenAI/Groq/... key (forwarded, never stored).
                                          A SentinelLLM key here instead selects the server's own cloud key.
  X-Sentinel-Key: <SentinelLLM key>     - identifies the caller (required when SENTINEL_REQUIRE_CLIENT_AUTH=true).
  X-Sentinel-Upstream: <name>           - optional; one of SENTINEL_PROXY_UPSTREAMS (default: the configured default).
Models named `ollama/<model>` go to the local Ollama server and need no provider key.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from sentinel.api.deps import _is_admin, _rate_limit, get_ctx
from sentinel.api.middleware import request_id_of
from sentinel.engine.proxy import ProxyError

router = APIRouter(prefix="/v1", tags=["OpenAI-compatible proxy"])


@dataclass
class ProxyCaller:
    authenticated: bool
    provider_key: str | None
    client_id: str | None


async def proxy_caller(request: Request) -> ProxyCaller:
    ctx = get_ctx(request)
    settings = ctx.settings
    if not settings.proxy_enabled:
        raise HTTPException(status_code=404, detail="The OpenAI-compatible proxy is disabled")

    def valid(key: str | None) -> bool:
        if not key:
            return False
        return _is_admin(settings, key) or any(hmac.compare_digest(key.encode(), k.encode()) for k in settings.client_keys)

    sentinel_key = (request.headers.get("x-sentinel-key") or request.headers.get("x-api-key") or "").strip() or None
    auth = request.headers.get("authorization", "")
    bearer = auth[7:].strip() if auth.lower().startswith("bearer ") else None
    if not sentinel_key and valid(bearer):
        sentinel_key, bearer = bearer, None  # caller sent its SentinelLLM key as the "API key"
    authenticated = valid(sentinel_key)
    if sentinel_key and not authenticated:
        raise ProxyError(401, "Invalid SentinelLLM key", code="invalid_sentinel_key", type_="authentication_error")
    if settings.require_client_auth and not authenticated:
        raise ProxyError(401, "Send your SentinelLLM key in the X-Sentinel-Key header", code="missing_sentinel_key",
                         type_="authentication_error")
    if authenticated:
        client_id = ctx.audit.client_id(sentinel_key)
    elif bearer:
        client_id = "byok_" + (ctx.audit.client_id(bearer) or "")[4:]  # HMAC of the provider key, never the key
    else:
        client_id = None
    await _rate_limit(request, client_id or f"ip:{request.client.host if request.client else 'unknown'}")
    return ProxyCaller(authenticated=authenticated, provider_key=bearer or None, client_id=client_id)


@router.post("/chat/completions", summary="OpenAI-compatible chat completions through the firewall")
async def chat_completions(request: Request):
    ctx = get_ctx(request)
    caller = await proxy_caller(request)
    try:
        body = await request.json()
    except ValueError:
        raise ProxyError(400, "Request body is not valid JSON", code="invalid_json") from None
    result = await ctx.proxy.chat(
        body, request_id=request_id_of(request), client_id=caller.client_id, provider_key=caller.provider_key,
        upstream_name=(request.headers.get("x-sentinel-upstream") or "").strip() or None,
        sentinel_authenticated=caller.authenticated,
    )
    headers = {"X-Sentinel-Decision": result.decision}
    if result.stream:
        return StreamingResponse(result.sse(), media_type="text/event-stream",
                                 headers={**headers, "Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
    return JSONResponse(result.body, headers=headers)


@router.get("/models", summary="Models reachable through the proxy")
async def list_models(request: Request) -> dict:
    ctx = get_ctx(request)
    await proxy_caller(request)
    data = []
    ollama = ctx.router.providers.get("ollama")
    if ollama is not None:
        try:
            data += [{"id": f"ollama/{m}", "object": "model", "created": 0, "owned_by": "ollama"} for m in await ollama.list_models()]
        except Exception:  # Ollama down: list the rest
            pass
    if ctx.settings.cloud_configured:
        data += [{"id": m, "object": "model", "created": 0, "owned_by": ctx.settings.cloud_provider_name}
                 for m in ctx.settings.cloud_model_list]
    return {"object": "list", "data": data}
