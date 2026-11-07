"""Module L - Tool execution security.

Every tool call proposed by an LLM (or an application) is checked against the
policy's tool registry before anything runs:

1. default-deny allowlist and per-tool enable switch
2. caller scope and read/write permission separation
3. strict argument validation (unknown/missing args, types, length, regex, enum, ranges)
4. argument content scanning (injection phrases, shell/SQL metacharacters, secrets)
5. per-session call-count limits (Redis counters)
6. approval requirements - an approval token is an HMAC bound to the exact
   session, tool and canonical arguments, issued only via the admin API
7. bounded execution of *simulated* tools with a timeout

An LLM response is never sufficient authorisation: VERIFY is not a valid tool
decision, and approval tokens can only be minted with the admin key.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
import time
from typing import Any, Literal

from pydantic import BaseModel, Field

from sentinel.detection.normalizer import normalize
from sentinel.detection.rules import INJECTION_RULES, RuleSet
from sentinel.detection.secret_detector import SecretDetector
from sentinel.engine.policy_schema import ArgSpec, ToolsPolicy
from sentinel.schemas.common import Decision
from sentinel.security.kv_store import KVStore
from sentinel.security.simulated_tools import SIMULATED_TOOLS

_SHELL_SQL = re.compile(
    r"(;\s*(rm|del|drop|shutdown|curl|wget|nc|bash|sh|powershell)\b|&&|\|\||`|\$\(|\bunion\s+select\b|\bdrop\s+table\b|"
    r"--\s*$|/\*|\bor\s+1\s*=\s*1\b|\.\./|\bexec(ute)?\s*\(|<script)",
    re.IGNORECASE,
)
_COUNTER_WINDOW = 24 * 3600


Permission = Literal["read", "write"]


def _read_only() -> list[Permission]:
    return ["read"]


class ToolCallRequest(BaseModel):
    tool_name: str = Field(min_length=1, max_length=64)
    arguments: dict[str, Any] = Field(default_factory=dict)
    session_id: str = Field(default="default", min_length=1, max_length=128)
    scope: str = Field(default="default", max_length=64)
    granted_permissions: list[Permission] = Field(default_factory=_read_only)
    approval_token: str | None = Field(default=None, max_length=256)
    execute: bool = False


class ArgViolation(BaseModel):
    argument: str
    problem: str


class ToolDecision(BaseModel):
    tool: str
    decision: Decision
    reasons: list[str] = Field(default_factory=list)
    violations: list[ArgViolation] = Field(default_factory=list)
    permission: str | None = None
    requires_approval: bool = False
    approved: bool = False
    calls_used: int | None = None
    calls_limit: int | None = None
    executed: bool = False
    result: Any = None
    execution_ms: float | None = None
    error: str | None = None


def canonical_args(arguments: dict[str, Any]) -> str:
    return json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _type_ok(spec: ArgSpec, value: Any) -> bool:
    if spec.type == "string" or spec.type == "enum":
        return isinstance(value, str)
    if spec.type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if spec.type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if spec.type == "boolean":
        return isinstance(value, bool)
    return False


class ToolGuard:
    def __init__(self, store: KVStore, secret: bytes) -> None:
        self.store = store
        self._secret = secret
        self._rules = RuleSet(INJECTION_RULES)
        self._secrets = SecretDetector()

    # -- approvals -----------------------------------------------------------
    def approval_token(self, session_id: str, tool_name: str, arguments: dict[str, Any]) -> str:
        msg = f"{session_id}|{tool_name}|{canonical_args(arguments)}".encode()
        return hmac.new(self._secret, b"tool-approval:" + msg, hashlib.sha256).hexdigest()

    def _approved(self, req: ToolCallRequest) -> bool:
        if not req.approval_token:
            return False
        expected = self.approval_token(req.session_id, req.tool_name, req.arguments)
        return hmac.compare_digest(expected, req.approval_token)

    # -- validation ------------------------------------------------------------
    def validate_arguments(self, specs: dict[str, ArgSpec], args: dict[str, Any], scan: bool) -> list[ArgViolation]:
        v: list[ArgViolation] = []
        for name in args:
            if name not in specs:
                v.append(ArgViolation(argument=name, problem="unknown argument"))
        for name, spec in specs.items():
            if name not in args:
                if spec.required:
                    v.append(ArgViolation(argument=name, problem="missing required argument"))
                continue
            value = args[name]
            if not _type_ok(spec, value):
                v.append(ArgViolation(argument=name, problem=f"expected {spec.type}"))
                continue
            if isinstance(value, str):
                if spec.max_length is not None and len(value) > spec.max_length:
                    v.append(ArgViolation(argument=name, problem=f"longer than {spec.max_length} characters"))
                if spec.pattern is not None and not re.fullmatch(spec.pattern, value):
                    v.append(ArgViolation(argument=name, problem="does not match the allowed pattern"))
                if spec.type == "enum" and value not in (spec.enum or []):
                    v.append(ArgViolation(argument=name, problem="value not in allowed set"))
                if scan:
                    if _SHELL_SQL.search(value):
                        v.append(ArgViolation(argument=name, problem="contains shell/SQL metacharacters or payload"))
                    n = normalize(value, max_chars=max(len(value), 100))
                    if self._rules.match(n.views, allow_dampening=False).score >= 0.6:
                        v.append(ArgViolation(argument=name, problem="contains instruction-injection content"))
                    spans, _, _ = self._secrets.find_spans(value)
                    if spans:
                        v.append(ArgViolation(argument=name, problem="contains credential material"))
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                if spec.minimum is not None and value < spec.minimum:
                    v.append(ArgViolation(argument=name, problem=f"below minimum {spec.minimum}"))
                if spec.maximum is not None and value > spec.maximum:
                    v.append(ArgViolation(argument=name, problem=f"above maximum {spec.maximum}"))
        return v

    def _counter_key(self, session_id: str, tool: str) -> str:
        return "toolcalls:" + hashlib.sha256(f"{session_id}|{tool}".encode()).hexdigest()[:32]

    async def evaluate(self, req: ToolCallRequest, policy: ToolsPolicy) -> ToolDecision:
        name = req.tool_name
        if not policy.enabled:
            return ToolDecision(tool=name, decision=Decision.BLOCK, reasons=["tool execution is disabled by policy"])
        spec = policy.tools.get(name)
        if spec is None:
            return ToolDecision(tool=name, decision=Decision.BLOCK, reasons=["tool is not on the allowlist (default deny)"])
        d = ToolDecision(tool=name, decision=Decision.ALLOW, permission=spec.permission,
                         requires_approval=spec.requires_approval, calls_limit=spec.max_calls_per_session)
        if not spec.enabled:
            d.reasons.append("tool is disabled by policy")
        if req.scope not in spec.allowed_scopes:
            d.reasons.append(f"scope '{req.scope}' is not permitted for this tool")
        if spec.permission == "write" and "write" not in req.granted_permissions:
            d.reasons.append("write permission not granted to this session")
        if spec.permission == "read" and "read" not in req.granted_permissions:
            d.reasons.append("read permission not granted to this session")
        d.violations = self.validate_arguments(spec.args, req.arguments, policy.scan_arguments)
        if d.violations:
            d.reasons.append(f"{len(d.violations)} argument violation(s)")
        raw = await self.store.get(self._counter_key(req.session_id, name))
        used = int(raw) if raw else 0
        d.calls_used = used
        if used >= spec.max_calls_per_session:
            d.reasons.append(f"call limit reached ({used}/{spec.max_calls_per_session})")
        if d.reasons:
            d.decision = Decision.BLOCK
            return d
        if spec.requires_approval:
            if self._approved(req):
                d.approved = True
                d.reasons.append("valid approval token for these exact arguments")
            else:
                d.decision = Decision.HUMAN_REVIEW
                d.reasons.append("tool requires human approval")
                return d
        d.reasons.append("all tool checks passed")
        return d

    async def execute(self, req: ToolCallRequest, decision: ToolDecision, policy: ToolsPolicy) -> ToolDecision:
        """Run the simulated tool if (and only if) the decision is ALLOW."""
        if decision.decision != Decision.ALLOW:
            return decision
        fn = SIMULATED_TOOLS.get(req.tool_name)
        if fn is None:
            decision.error = "no simulated implementation for this tool"
            return decision
        spec = policy.tools[req.tool_name]
        decision.calls_used = await self.store.incr_window(self._counter_key(req.session_id, req.tool_name), _COUNTER_WINDOW)
        start = time.perf_counter()
        try:
            decision.result = await asyncio.wait_for(fn(**req.arguments), timeout=spec.timeout_seconds)
            decision.executed = True
        except asyncio.TimeoutError:
            decision.error = "tool execution timed out"
        except (ValueError, TypeError, ZeroDivisionError, SyntaxError) as exc:
            decision.error = f"tool rejected input: {type(exc).__name__}"
        decision.execution_ms = round((time.perf_counter() - start) * 1000, 2)
        return decision
