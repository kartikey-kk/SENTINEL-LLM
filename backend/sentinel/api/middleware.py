"""ASGI middleware: request IDs, request-size limits, security headers, safe errors."""

from __future__ import annotations

import logging
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sentinel.audit.service import AuditError
from sentinel.detection.normalizer import InputValidationError
from sentinel.engine.policy_engine import PolicyValidationError
from sentinel.providers.base import ProviderError

logger = logging.getLogger("sentinel.api")


def new_request_id() -> str:
    return "req_" + uuid.uuid4().hex


class RequestContextMiddleware:
    """Assigns a server-generated request ID and enforces a maximum body size."""

    def __init__(self, app: ASGIApp, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = new_request_id()
        scope.setdefault("state", {})["request_id"] = request_id

        headers = dict(scope.get("headers") or [])
        declared = headers.get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.max_body_bytes:
            await _send_json(send, 413, "request_too_large", f"Request body exceeds {self.max_body_bytes} bytes", request_id)
            return

        received = 0
        too_large = False

        async def limited_receive() -> Message:
            nonlocal received, too_large
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_bytes:
                    too_large = True
                    raise _BodyTooLarge()
            return message

        replaced = False

        async def send_with_headers(message: Message) -> None:
            nonlocal replaced
            if too_large:
                # The framework converted our exception into an error response; replace it with a 413.
                if not replaced:
                    replaced = True
                    await _send_json(send, 413, "request_too_large",
                                     f"Request body exceeds {self.max_body_bytes} bytes", request_id)
                return
            if message["type"] == "http.response.start":
                hdrs = list(message.get("headers", []))
                hdrs += [
                    (b"x-request-id", request_id.encode()),
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"cache-control", b"no-store"),
                ]
                message["headers"] = hdrs
            await send(message)

        try:
            await self.app(scope, limited_receive, send_with_headers)
        except _BodyTooLarge:
            if not replaced:
                await _send_json(send, 413, "request_too_large", f"Request body exceeds {self.max_body_bytes} bytes", request_id)


class _BodyTooLarge(Exception):
    pass


async def _send_json(send: Send, status: int, code: str, message: str, request_id: str) -> None:
    import json

    body = json.dumps({"error": {"code": code, "message": message, "request_id": request_id}}).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"x-request-id", request_id.encode())]})
    await send({"type": "http.response.body", "body": body})


def request_id_of(request: Request) -> str:
    return getattr(request.state, "request_id", None) or new_request_id()


def _error(request: Request, status: int, code: str, message: str, extra: dict | None = None,
           headers: dict | None = None) -> JSONResponse:
    payload = {"error": {"code": code, "message": message, "request_id": request_id_of(request)}}
    if extra:
        payload["error"].update(extra)
    return JSONResponse(status_code=status, content=payload, headers=headers)


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(HTTPException)
    async def _http(request: Request, exc: HTTPException) -> JSONResponse:
        code = {400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found", 409: "conflict",
                413: "request_too_large", 429: "rate_limited", 503: "unavailable"}.get(exc.status_code, "error")
        return _error(request, exc.status_code, code, str(exc.detail), headers=getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Never echo submitted values back (they may contain secrets).
        details = [{"loc": [str(x) for x in e.get("loc", [])], "msg": e.get("msg", ""), "type": e.get("type", "")}
                   for e in exc.errors()][:20]
        return _error(request, 422, "validation_error", "Request validation failed", {"details": details})

    @app.exception_handler(InputValidationError)
    async def _input(request: Request, exc: InputValidationError) -> JSONResponse:
        return _error(request, exc.status, exc.code, str(exc))

    @app.exception_handler(PolicyValidationError)
    async def _policy(request: Request, exc: PolicyValidationError) -> JSONResponse:
        return _error(request, 422, "policy_validation_error", "Policy validation failed", {"details": exc.errors})

    @app.exception_handler(ProviderError)
    async def _provider(request: Request, exc: ProviderError) -> JSONResponse:
        return _error(request, exc.status, exc.code, exc.message)

    @app.exception_handler(AuditError)
    async def _audit(request: Request, exc: AuditError) -> JSONResponse:
        return _error(request, 503, "audit_unavailable", "Audit log unavailable; request refused (fail closed)")

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled error on %s %s", request.method, request.url.path)
        return _error(request, 500, "internal_error", "Internal server error")
