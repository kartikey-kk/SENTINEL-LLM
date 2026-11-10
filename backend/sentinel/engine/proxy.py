"""OpenAI-compatible proxy: SentinelLLM as drop-in middleware between an app and its model provider.

An app keeps its OpenAI SDK (or LangChain, LlamaIndex, raw HTTP...) and only changes `base_url` to
SentinelLLM's `/v1`. Each `/v1/chat/completions` call is:

  1. resolved to an upstream from a NAMED allowlist (callers can never supply a URL),
  2. inspected: the latest user message goes through the full input pipeline; earlier user/assistant
     turns are redacted; tool-role messages are scanned as untrusted context,
  3. forwarded with the caller's own provider key (bring-your-own-key; never stored or logged) or,
     for callers authenticated with a SentinelLLM key, the server's configured cloud key,
  4. validated on the way back (content and tool-call arguments), and
  5. audited like every other SentinelLLM decision.

Streaming requests are answered as Server-Sent Events, but only after the complete answer has passed
output validation: the first token arrives later, and output checks are never skipped.
"""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

import httpx

from sentinel.config import Settings
from sentinel.detection.context_detector import ContextChunk
from sentinel.detection.pii_detector import options_from_policy
from sentinel.engine.enforcement import BLOCK_MESSAGE, Redactor, collect_spans
from sentinel.engine.pipeline import OUTPUT_WITHHELD, SentinelPipeline
from sentinel.engine.policy_engine import ProviderContext, effective_threshold
from sentinel.engine.policy_schema import SentinelPolicy
from sentinel.providers.base import classify_http_error
from sentinel.schemas.common import Decision, DetectionResult

TOOL_OUTPUT_REMOVED = "[SentinelLLM removed this tool output: it contained embedded instructions]"
TOOL_OUTPUT_OMITTED = "[SentinelLLM omitted this tool output: too many tool outputs to inspect in one request]"
MAX_MESSAGES = 500
_TEXT_ROLES = {"system", "developer", "user", "assistant", "tool", "function"}


class ProxyError(Exception):
    """An error returned to the caller in OpenAI's error format."""

    def __init__(self, status: int, message: str, *, code: str, type_: str = "invalid_request_error",
                 param: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.code = code
        self.type = type_
        self.param = param


@dataclass
class Upstream:
    name: str
    base_url: str
    is_local: bool
    key: str | None = field(repr=False)
    byok: bool = False


@dataclass
class ProxyResult:
    body: dict[str, Any]
    stream: bool
    include_usage: bool
    decision: str

    async def sse(self) -> AsyncIterator[bytes]:
        """Replay a validated completion as `chat.completion.chunk` events."""
        c = self.body
        base = {"id": c["id"], "object": "chat.completion.chunk", "created": c["created"], "model": c["model"]}

        def event(payload: dict[str, Any]) -> bytes:
            return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode()

        for choice in c["choices"]:
            idx, msg = choice["index"], choice.get("message") or {}
            yield event({**base, "choices": [{"index": idx, "delta": {"role": "assistant", "content": ""}, "finish_reason": None}]})
            text = msg.get("content") or ""
            for i in range(0, len(text), 80):
                yield event({**base, "choices": [{"index": idx, "delta": {"content": text[i:i + 80]}, "finish_reason": None}]})
            if msg.get("tool_calls"):
                calls = [{"index": n, "id": tc.get("id"), "type": tc.get("type", "function"), "function": tc.get("function", {})}
                         for n, tc in enumerate(msg["tool_calls"])]
                yield event({**base, "choices": [{"index": idx, "delta": {"tool_calls": calls}, "finish_reason": None}]})
            yield event({**base, "choices": [{"index": idx, "delta": {}, "finish_reason": choice.get("finish_reason")}],
                         "sentinel": c.get("sentinel")})
        if self.include_usage:
            yield event({**base, "choices": [], "usage": c.get("usage")})
        yield b"data: [DONE]\n\n"


def _text_of(content: Any) -> str | None:
    """Text of an OpenAI message `content` (string or list of text parts). Non-text parts are refused:
    SentinelLLM cannot inspect them, and forwarding them unchecked would bypass the firewall."""
    if content is None:
        return None
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for p in content:
            if not isinstance(p, dict):
                raise ProxyError(400, "Invalid message content part", code="invalid_content", param="messages")
            kind = p.get("type")
            if kind != "text":
                raise ProxyError(400, f"Content parts of type '{kind}' are not supported: SentinelLLM can only inspect text",
                                 code="unsupported_content", param="messages")
            parts.append(str(p.get("text", "")))
        return "\n".join(parts)
    raise ProxyError(400, "Invalid message content", code="invalid_content", param="messages")


class ChatProxy:
    def __init__(self, settings: Settings, pipeline: SentinelPipeline) -> None:
        self.settings = settings
        self.pipeline = pipeline
        self.upstreams = settings.proxy_upstream_map
        self.http = httpx.AsyncClient(timeout=httpx.Timeout(settings.provider_timeout_seconds, connect=10.0))

    async def aclose(self) -> None:
        await self.http.aclose()

    # ------------------------------------------------------------------ upstream
    def resolve(self, model: str, upstream_name: str | None, provider_key: str | None,
                sentinel_authenticated: bool) -> tuple[Upstream, str]:
        s = self.settings
        if model.startswith("ollama/"):
            if not s.ollama_enabled:
                raise ProxyError(400, "The local Ollama upstream is disabled", code="upstream_disabled", param="model")
            return Upstream("ollama", s.ollama_base_url.rstrip("/") + "/v1", True, None), model[len("ollama/"):]
        if provider_key:
            if not s.proxy_allow_byok:
                raise ProxyError(403, "This SentinelLLM does not accept caller provider keys", code="byok_disabled")
            name = (upstream_name or s.proxy_default_upstream).lower()
            if name not in self.upstreams:
                raise ProxyError(400, f"Unknown upstream '{name}'. Available: {', '.join(sorted(self.upstreams)) or 'none'}",
                                 code="unknown_upstream")
            return Upstream(name, self.upstreams[name], False, provider_key, byok=True), model
        if sentinel_authenticated and s.cloud_configured:
            if upstream_name and upstream_name.lower() not in ("cloud", s.cloud_provider_name.lower()):
                raise ProxyError(400, "A named upstream needs your own provider key (Authorization: Bearer <key>)",
                                 code="missing_provider_key")
            return Upstream(s.cloud_provider_name, s.cloud_base_url.rstrip("/"), False,
                            s.cloud_api_key.get_secret_value()), model
        raise ProxyError(401, "Send your provider API key as 'Authorization: Bearer <key>', or use an 'ollama/<model>' model",
                         code="missing_provider_key", type_="authentication_error")

    async def _forward(self, upstream: Upstream, payload: dict[str, Any]) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if upstream.key:
            headers["Authorization"] = f"Bearer {upstream.key}"
        try:
            resp = await self.http.post(f"{upstream.base_url}/chat/completions", json=payload, headers=headers)
        except httpx.HTTPError as exc:
            err = classify_http_error(exc, upstream.name)
            raise ProxyError(err.status, err.message, code=err.code, type_="upstream_error") from None
        if resp.status_code >= 400:
            # Upstream bodies are never echoed for auth errors (they can quote parts of the key).
            detail = ""
            if resp.status_code not in (401, 403):
                try:
                    detail = str((resp.json().get("error") or {}).get("message", ""))[:300]
                except (ValueError, AttributeError):
                    detail = ""
            status = resp.status_code if resp.status_code in (400, 401, 403, 404, 422, 429) else 502
            msg = {401: f"{upstream.name} rejected the provider key", 403: f"{upstream.name} refused access",
                   429: f"{upstream.name} rate limited the request"}.get(resp.status_code, f"{upstream.name} returned an error")
            raise ProxyError(status, f"{msg}: {detail}" if detail else msg, code=f"upstream_{resp.status_code}", type_="upstream_error")
        try:
            data = resp.json()
        except ValueError:
            raise ProxyError(502, f"{upstream.name} returned an invalid response", code="upstream_invalid") from None
        if not isinstance(data, dict) or not isinstance(data.get("choices"), list):
            raise ProxyError(502, f"{upstream.name} returned an invalid response", code="upstream_invalid")
        return data

    # ------------------------------------------------------------------ helpers
    async def _redact(self, text: str, redactor: Redactor, policy: SentinelPolicy) -> str:
        spans = self.pipeline.secret.find_spans(text)[0] + await self.pipeline.pii.find_spans(text, options_from_policy(policy.pii))
        if not spans:
            return text
        fake = DetectionResult(detector="history")
        fake.set_spans(spans)
        out, _ = redactor.redact(text, collect_spans({"pii": fake}, {"pii", "secret"}))
        return out

    def _completion(self, request_id: str, model: str, content: str, finish_reason: str, sentinel: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": f"chatcmpl-{request_id}", "object": "chat.completion", "created": int(time.time()), "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": finish_reason,
                         "logprobs": None}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "sentinel": sentinel,
        }

    # ------------------------------------------------------------------ main
    async def chat(self, body: Any, *, request_id: str, client_id: str | None, provider_key: str | None,
                   upstream_name: str | None, sentinel_authenticated: bool) -> ProxyResult:
        start = time.perf_counter()
        if not isinstance(body, dict):
            raise ProxyError(400, "Request body must be a JSON object", code="invalid_request")
        model = body.get("model")
        messages = body.get("messages")
        if not isinstance(model, str) or not model.strip() or len(model) > 200:
            raise ProxyError(400, "'model' is required", code="invalid_model", param="model")
        if not isinstance(messages, list) or not 1 <= len(messages) <= MAX_MESSAGES:
            raise ProxyError(400, f"'messages' must be a list of 1 to {MAX_MESSAGES} messages", code="invalid_messages", param="messages")
        stream = bool(body.get("stream", False))
        include_usage = bool((body.get("stream_options") or {}).get("include_usage")) if stream else False

        upstream, upstream_model = self.resolve(model, upstream_name, provider_key, sentinel_authenticated)
        policy = self.pipeline.policy_store.current
        # Policy treats every remote upstream as the cloud provider class; Ollama as local.
        pctx = ProviderContext(name="ollama" if upstream.is_local else "openai_compatible", is_local=upstream.is_local)
        redact_pii = policy.pii.action == Decision.REDACT or (not upstream.is_local and policy.providers.cloud_requires_pii_redaction)

        parsed: list[tuple[dict[str, Any], str, str | None]] = []
        for i, m in enumerate(messages):
            if not isinstance(m, dict) or m.get("role") not in _TEXT_ROLES:
                raise ProxyError(400, f"messages[{i}] has an unsupported role", code="invalid_role", param="messages")
            parsed.append((m, m["role"], _text_of(m.get("content"))))
        last_user = max((i for i, (_, role, text) in enumerate(parsed) if role == "user" and text is not None), default=None)

        redactor = Redactor()
        stages: dict[str, dict[str, DetectionResult]] = {}
        metadata: dict[str, Any] = {"upstream": upstream.name, "byok": upstream.byok, "stream": stream,
                                    "messages": len(messages), "model": upstream_model}
        sentinel: dict[str, Any] = {"request_id": request_id}
        user_text: str = (parsed[last_user][2] or "") if last_user is not None else ""
        preview = ""

        async def audit(decision: str, output_decision: str | None, risk: float = 0.0, extra: list[str] | None = None,
                        usage: dict[str, Any] | None = None, llm_ms: float | None = None) -> None:
            latency = round((time.perf_counter() - start) * 1000, 2)
            await self.pipeline.audit.record_event(
                request_id=request_id, event_type="proxy", decision=decision, output_decision=output_decision,
                stages=stages, risk_score=risk, provider=f"proxy:{upstream.name}", model=upstream_model, latency_ms=latency,
                raw_input=user_text or None, sanitized_preview=preview or None, policy_version=policy.version,
                client_id=client_id, metadata=metadata, extra_categories=extra,
            )
            await self.pipeline.audit.record_metric(
                request_id=request_id, endpoint="proxy", provider=f"proxy:{upstream.name}", model=upstream_model,
                decision=decision, total_latency_ms=latency, llm_latency_ms=llm_ms,
                prompt_tokens=(usage or {}).get("prompt_tokens"), completion_tokens=(usage or {}).get("completion_tokens"),
            )

        def blocked(reason_text: str, decision: Decision) -> ProxyResult:
            if self.settings.proxy_block_mode == "error":
                raise ProxyError(400, reason_text, code="sentinel_blocked", type_="sentinel_policy_violation")
            body_out = self._completion(request_id, model, reason_text, "content_filter", sentinel)
            return ProxyResult(body=body_out, stream=stream, include_usage=include_usage, decision=decision.value)

        # --- 1. latest user message: full input inspection -----------------------------------------
        risk = 0.0
        input_redacted = False
        sanitized_user = None
        if last_user is not None:
            history = [{"role": role, "content": text} for (_, role, text) in parsed[:last_user]
                       if role in ("user", "assistant") and text]
            ins = await self.pipeline.inspect_input(user_text, policy=policy, provider_ctx=pctx, history=history, redactor=redactor)
            stages["input"] = ins.results
            risk = ins.risk.score
            preview = ins.enforcement.sanitized_text
            sentinel.update(input_decision=ins.final_decision.value,
                            reasons=ins.policy_decision.summary, redactions=len(ins.enforcement.redactions))
            metadata["policy_reasons"] = [r.model_dump(mode="json") for r in ins.policy_decision.reasons]
            if not ins.enforcement.forward:
                sentinel["decision"] = ins.final_decision.value
                await audit(ins.final_decision.value, None, risk)
                return blocked(ins.enforcement.message or BLOCK_MESSAGE, ins.final_decision)
            sanitized_user = ins.enforcement.sanitized_text
            input_redacted = bool(ins.enforcement.redactions)

        # --- 2. tool outputs: untrusted context ------------------------------------------------------
        tool_idx = [i for i, (_, role, text) in enumerate(parsed) if role in ("tool", "function") and text is not None]
        verdicts: dict[str, Any] = {}
        context_flagged = 0
        if tool_idx:
            chunks = [ContextChunk(id=f"msg-{i}", source_type="tool_output",
                                   source=str(parsed[i][0].get("name") or parsed[i][0].get("tool_call_id") or "")[:200] or None,
                                   text=parsed[i][2] or "") for i in tool_idx]
            ci = await self.pipeline.context.inspect(chunks, policy.context,
                                                     threshold=effective_threshold(policy, "context", None),
                                                     redact_pii=redact_pii, redactor=redactor)
            verdicts = {c.id: c for c in ci.chunks}
            context_flagged = ci.flagged_count
            stages["context"] = {c.id: DetectionResult(detector="context", detected=c.flagged, score=c.risk, confidence=c.ml_score,
                                                       reason="; ".join(c.reasons)[:400] or "no indicators", method=policy.context.mode)
                                 for c in ci.chunks}
            metadata["tool_outputs"] = [{"id": c.id, "risk": c.risk, "action": c.action, "included": c.included} for c in ci.chunks]
            if ci.decision == Decision.BLOCK:
                sentinel["decision"] = "BLOCK"
                await audit("BLOCK", None, max(risk, ci.max_risk), extra=["indirect_injection"])
                return blocked("The request was blocked because a tool output contained embedded instructions.", Decision.BLOCK)

        # --- 3. rebuild the message list ---------------------------------------------------------------
        out_messages: list[dict[str, Any]] = []
        for i, (m, role, text) in enumerate(parsed):
            new = dict(m)
            if i == last_user and sanitized_user is not None:
                new["content"] = sanitized_user
            elif role in ("tool", "function") and text is not None:
                v = verdicts.get(f"msg-{i}")
                new["content"] = TOOL_OUTPUT_OMITTED if v is None else (v.sanitized_text if v.included else TOOL_OUTPUT_REMOVED)
            elif role in ("user", "assistant") and text:
                new["content"] = await self._redact(text, redactor, policy) if redact_pii else text
            # system / developer messages are the application's own trusted instructions: forwarded as sent.
            out_messages.append(new)

        payload = {k: v for k, v in body.items() if k not in ("messages", "model", "stream", "stream_options")}
        payload.update(model=upstream_model, messages=out_messages, stream=False)
        for key in ("max_tokens", "max_completion_tokens"):
            if isinstance(payload.get(key), int):
                payload[key] = min(payload[key], policy.providers.max_output_tokens)

        # --- 4. forward ---------------------------------------------------------------------------------
        t_llm = time.perf_counter()
        try:
            data = await self._forward(upstream, payload)
        except ProxyError:
            metadata["upstream_error"] = True
            sentinel["decision"] = "ALLOW"
            await audit("ALLOW", None, risk)
            raise
        llm_ms = round((time.perf_counter() - t_llm) * 1000, 2)

        # --- 5. validate every choice ------------------------------------------------------------------
        system_prompt = "\n".join(t for (_, role, t) in parsed if role in ("system", "developer") and t) or None
        raw_fmt = body.get("response_format")
        fmt: dict[str, Any] = raw_fmt if isinstance(raw_fmt, dict) else {}
        response_format = "json" if fmt.get("type") in ("json_object", "json_schema") else "text"
        json_schema = ((fmt.get("json_schema") or {}).get("schema")) if fmt.get("type") == "json_schema" else None
        output_decisions: list[Decision] = []
        output_redacted = False
        failed_checks: list[str] = []
        for choice in data["choices"]:
            msg = choice.get("message") or {}
            content = msg.get("content")
            decision = Decision.ALLOW
            if isinstance(content, str) and content:
                ov = await self.pipeline.output_validator.validate(
                    content, policy, system_prompt=system_prompt, response_format=response_format if not msg.get("tool_calls") else "text",
                    json_schema=json_schema, max_chars=200_000)
                stages.setdefault("output", ov.results)
                failed_checks += [f"output_{c.check}" for c in ov.failed_checks if c.action != Decision.ALLOW]
                decision = ov.decision
                if ov.decision == Decision.REDACT:
                    msg["content"] = ov.sanitized_text
                    output_redacted = True
            for tc in msg.get("tool_calls") or []:
                args = str(((tc or {}).get("function") or {}).get("arguments") or "")
                if self.pipeline.secret.find_spans(args)[0]:
                    decision = Decision.BLOCK
                    failed_checks.append("output_tool_call_secret")
            if decision == Decision.BLOCK:
                choice["message"] = {"role": "assistant", "content": OUTPUT_WITHHELD}
                choice["finish_reason"] = "content_filter"
            output_decisions.append(decision)

        if output_decisions and all(d == Decision.BLOCK for d in output_decisions):
            overall = Decision.BLOCK
        elif input_redacted or output_redacted or context_flagged or any(d == Decision.BLOCK for d in output_decisions):
            overall = Decision.REDACT
        else:
            overall = Decision.ALLOW
        out_decision = max(output_decisions, key=lambda d: {Decision.ALLOW: 0, Decision.REDACT: 1, Decision.BLOCK: 2}.get(d, 0),
                           default=Decision.ALLOW)
        sentinel.update(decision=overall.value, output_decision=out_decision.value,
                        tool_outputs_removed=sum(1 for v in verdicts.values() if not v.included))
        await audit(overall.value, out_decision.value, risk, extra=sorted(set(failed_checks)) or None,
                    usage=data.get("usage") if isinstance(data.get("usage"), dict) else None, llm_ms=llm_ms)

        data["sentinel"] = sentinel
        data.setdefault("id", f"chatcmpl-{request_id}")
        data.setdefault("created", int(time.time()))
        data.setdefault("model", upstream_model)
        return ProxyResult(body=data, stream=stream, include_usage=include_usage, decision=overall.value)
