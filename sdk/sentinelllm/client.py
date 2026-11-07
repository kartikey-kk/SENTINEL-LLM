"""SentinelLLM Python SDK clients (sync and async)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

import httpx

from sentinelllm._models import ChatResult, ContextInspection, InputInspection, OutputInspection, Result, ToolDecision
from sentinelllm.exceptions import BlockedError, SentinelError

DEFAULT_URL = "http://localhost:8000"


def _chunks(chunks: Iterable[str | Mapping[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for i, c in enumerate(chunks):
        if isinstance(c, str):
            out.append({"id": f"chunk-{i}", "text": c})
        else:
            out.append(dict(c))
    return out


def _history(history: Sequence[Mapping[str, str]] | None) -> list[dict[str, str]]:
    return [{"role": m["role"], "content": m["content"]} for m in (history or [])]


def _raise_for(resp: httpx.Response) -> None:
    if resp.is_success:
        return
    try:
        err = resp.json().get("error", {})
    except ValueError:
        err = {}
    raise SentinelError(resp.status_code, err.get("code", "http_error"), err.get("message", resp.reason_phrase),
                        err.get("request_id") or resp.headers.get("x-request-id"), err.get("details"))


def _chat_payload(message: str, provider: str | None, model: str | None, **kw: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"message": message}
    if provider:
        payload["provider"] = provider
    if model:
        payload["model"] = model
    if kw.get("history"):
        payload["history"] = _history(kw["history"])
    if kw.get("context"):
        payload["context"] = _chunks(kw["context"])
    for key in ("system_prompt", "session_id", "context_profile", "json_schema", "evidence"):
        if kw.get(key) is not None:
            payload[key] = kw[key]
    payload["response_format"] = kw.get("response_format", "text")
    payload["restore_pii"] = bool(kw.get("restore_pii", False))
    payload["temperature"] = kw.get("temperature", 0.2)
    payload["max_tokens"] = kw.get("max_tokens", 512)
    return payload


class Sentinel:
    """Synchronous client.

    >>> firewall = Sentinel(base_url="http://localhost:8000")
    >>> r = firewall.secure_chat("Explain machine learning", provider="ollama", model="qwen2.5:3b")
    >>> r.text, r.security.decision
    """

    def __init__(self, base_url: str = DEFAULT_URL, api_key: str | None = None, *, timeout: float = 180.0,
                 raise_on_block: bool = False, transport: httpx.BaseTransport | None = None) -> None:
        headers = {"User-Agent": "sentinelllm-sdk/0.1"}
        if api_key:
            headers["X-API-Key"] = api_key
        self.raise_on_block = raise_on_block
        self._http = httpx.Client(base_url=base_url.rstrip("/"), headers=headers, timeout=timeout, transport=transport)

    # -- lifecycle --------------------------------------------------------------
    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "Sentinel":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        resp = self._http.post(path, json=payload)
        _raise_for(resp)
        return resp.json()

    def _get(self, path: str) -> dict[str, Any]:
        resp = self._http.get(path)
        _raise_for(resp)
        return resp.json()

    # -- API ----------------------------------------------------------------------
    def secure_chat(self, message: str, provider: str | None = None, model: str | None = None, **kwargs: Any) -> ChatResult:
        """Send a message through the full firewall pipeline. See ``ChatRequest`` for keyword options:
        system_prompt, history, context, session_id, context_profile, response_format, json_schema,
        evidence, restore_pii, temperature, max_tokens."""
        result = ChatResult(self._post("/api/v1/chat", _chat_payload(message, provider, model, **kwargs)))
        if self.raise_on_block and result.blocked:
            raise BlockedError(result)
        return result

    def inspect_input(self, text: str, *, provider: str | None = None, session_id: str | None = None,
                      context_profile: str | None = None, history: Sequence[Mapping[str, str]] | None = None,
                      content_type: str = "text", verify: bool = True) -> InputInspection:
        payload: dict[str, Any] = {"text": text, "content_type": content_type, "verify": verify, "history": _history(history)}
        for k, v in (("provider", provider), ("session_id", session_id), ("context_profile", context_profile)):
            if v is not None:
                payload[k] = v
        return InputInspection(self._post("/api/v1/inspect/input", payload))

    def inspect_output(self, text: str, *, system_prompt: str | None = None, canary: str | None = None,
                       response_format: str = "text", json_schema: dict[str, Any] | None = None,
                       evidence: list[str] | None = None) -> OutputInspection:
        payload: dict[str, Any] = {"text": text, "response_format": response_format}
        for k, v in (("system_prompt", system_prompt), ("canary", canary), ("json_schema", json_schema), ("evidence", evidence)):
            if v is not None:
                payload[k] = v
        return OutputInspection(self._post("/api/v1/inspect/output", payload))

    def inspect_context(self, chunks: Iterable[str | Mapping[str, Any]], *, provider: str | None = None,
                        context_profile: str | None = None) -> ContextInspection:
        payload: dict[str, Any] = {"chunks": _chunks(chunks)}
        if provider:
            payload["provider"] = provider
        if context_profile:
            payload["context_profile"] = context_profile
        return ContextInspection(self._post("/api/v1/inspect/context", payload))

    def inspect_tool(self, tool_name: str, arguments: Mapping[str, Any] | None = None, *, session_id: str = "default",
                     scope: str = "default", granted_permissions: Sequence[str] = ("read",),
                     approval_token: str | None = None, execute: bool = False) -> ToolDecision:
        payload: dict[str, Any] = {"tool_name": tool_name, "arguments": dict(arguments or {}), "session_id": session_id,
                                   "scope": scope, "granted_permissions": list(granted_permissions), "execute": execute}
        if approval_token:
            payload["approval_token"] = approval_token
        return ToolDecision(self._post("/api/v1/inspect/tool", payload))

    def health(self) -> Result:
        return Result(self._get("/api/v1/health"))

    def models(self) -> Result:
        return Result(self._get("/api/v1/models"))


class AsyncSentinel:
    """Async client with the same methods as :class:`Sentinel`."""

    def __init__(self, base_url: str = DEFAULT_URL, api_key: str | None = None, *, timeout: float = 180.0,
                 raise_on_block: bool = False, transport: httpx.AsyncBaseTransport | None = None) -> None:
        headers = {"User-Agent": "sentinelllm-sdk/0.1"}
        if api_key:
            headers["X-API-Key"] = api_key
        self.raise_on_block = raise_on_block
        self._http = httpx.AsyncClient(base_url=base_url.rstrip("/"), headers=headers, timeout=timeout, transport=transport)

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> "AsyncSentinel":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    async def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        resp = await self._http.post(path, json=payload)
        _raise_for(resp)
        return resp.json()

    async def secure_chat(self, message: str, provider: str | None = None, model: str | None = None, **kwargs: Any) -> ChatResult:
        result = ChatResult(await self._post("/api/v1/chat", _chat_payload(message, provider, model, **kwargs)))
        if self.raise_on_block and result.blocked:
            raise BlockedError(result)
        return result

    async def inspect_input(self, text: str, **kwargs: Any) -> InputInspection:
        payload: dict[str, Any] = {"text": text, **{k: v for k, v in kwargs.items() if v is not None}}
        if "history" in payload:
            payload["history"] = _history(payload["history"])
        return InputInspection(await self._post("/api/v1/inspect/input", payload))

    async def inspect_output(self, text: str, **kwargs: Any) -> OutputInspection:
        return OutputInspection(await self._post("/api/v1/inspect/output", {"text": text, **{k: v for k, v in kwargs.items() if v is not None}}))

    async def inspect_context(self, chunks: Iterable[str | Mapping[str, Any]], **kwargs: Any) -> ContextInspection:
        return ContextInspection(await self._post("/api/v1/inspect/context", {"chunks": _chunks(chunks), **{k: v for k, v in kwargs.items() if v is not None}}))

    async def inspect_tool(self, tool_name: str, arguments: Mapping[str, Any] | None = None, **kwargs: Any) -> ToolDecision:
        payload = {"tool_name": tool_name, "arguments": dict(arguments or {}), **{k: v for k, v in kwargs.items() if v is not None}}
        if "granted_permissions" in payload:
            payload["granted_permissions"] = list(payload["granted_permissions"])
        return ToolDecision(await self._post("/api/v1/inspect/tool", payload))
