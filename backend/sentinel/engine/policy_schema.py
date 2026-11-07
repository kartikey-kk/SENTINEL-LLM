"""Policy document schema and validation.

The policy is the single source of truth for thresholds, actions, provider
permissions, output rules, context rules and tool permissions. It is loaded
from YAML, can be updated per section through the admin API, and is validated
here. Several safety invariants are enforced at validation time so they cannot
be configured away:

* Secrets can only be BLOCKed or REDACTed (never ALLOW/VERIFY).
* Critical detectors (prompt injection, jailbreak, secrets, PII) cannot use
  ``on_error: ALLOW`` - a failed check never counts as a pass.
* Prompt injection / jailbreak / secrets may not use VERIFY as their action:
  an LLM verifier can only *escalate*, never authorise a detected attack.
* Verification is escalate-only.
* Context-profile threshold multipliers are bounded so a profile cannot
  effectively disable a detector.
* Tool decisions never use VERIFY (an LLM response is never the sole
  authorisation for a tool call).
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from sentinel.schemas.common import Decision

Mode = Literal["rules", "ml", "hybrid"]
_CRITICAL_ON_ERROR = {Decision.BLOCK, Decision.HUMAN_REVIEW}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class DetectorPolicy(_Strict):
    enabled: bool = True
    threshold: float = Field(default=0.8, ge=0.05, le=1.0)
    action: Decision = Decision.BLOCK
    on_error: Decision = Decision.BLOCK
    mode: Mode = "hybrid"
    verify_band: tuple[float, float] | None = Field(
        default=None, description="Scores in [low, high) trigger escalate-only secondary verification"
    )
    ml_weight: float = Field(
        default=1.0, ge=0.0, le=1.0,
        description="Hybrid mode: trust weight applied to the classifier probability when no deterministic rule corroborates it",
    )

    @model_validator(mode="after")
    def _band(self) -> "DetectorPolicy":
        if self.verify_band is not None:
            lo, hi = self.verify_band
            if not (0.0 <= lo < hi <= 1.0):
                raise ValueError("verify_band must satisfy 0 <= low < high <= 1")
            if hi > self.threshold:
                raise ValueError("verify_band upper bound must not exceed the detection threshold")
        return self


class CustomPattern(_Strict):
    regex: str = Field(max_length=300)
    score: float = Field(default=0.8, ge=0.0, le=1.0)

    @field_validator("regex")
    @classmethod
    def _compiles(cls, v: str) -> str:
        try:
            re.compile(v)
        except re.error as exc:
            raise ValueError(f"invalid regex: {exc}") from exc
        return v


class CustomEntity(_Strict):
    name: str = Field(pattern=r"^[A-Z][A-Z0-9_]{1,40}$")
    patterns: list[CustomPattern] = Field(min_length=1, max_length=10)
    context: list[str] = Field(default_factory=list, max_length=20)
    sensitivity: float = Field(default=0.6, ge=0.0, le=1.0)


class PIIPolicy(_Strict):
    enabled: bool = True
    action: Decision = Decision.REDACT
    on_error: Decision = Decision.BLOCK
    score_threshold: float = Field(default=0.4, ge=0.0, le=1.0)
    entity_thresholds: dict[str, float] = Field(default_factory=dict)
    entities: list[str] = Field(default_factory=list)
    block_entities: list[str] = Field(default_factory=list)
    allow_list: list[str] = Field(default_factory=list, max_length=500)
    custom_entities: list[CustomEntity] = Field(default_factory=list, max_length=50)
    allow_restoration: bool = False
    restoration_ttl_seconds: int = Field(default=900, ge=30, le=86400)


class SecretPolicy(_Strict):
    enabled: bool = True
    action: Decision = Decision.BLOCK
    on_error: Decision = Decision.BLOCK
    entropy: bool = True
    min_weight: float = Field(default=0.6, ge=0.0, le=1.0)

    @field_validator("action")
    @classmethod
    def _secret_action(cls, v: Decision) -> Decision:
        if v not in (Decision.BLOCK, Decision.REDACT):
            raise ValueError("secret_detection.action must be BLOCK or REDACT")
        return v


class ToxicityPolicy(_Strict):
    enabled: bool = True
    threshold: float = Field(default=0.85, ge=0.05, le=1.0)
    action: Decision = Decision.VERIFY
    on_error: Decision = Decision.ALLOW


class RiskWeights(_Strict):
    prompt_injection: float = Field(default=0.40, ge=0.0)
    jailbreak: float = Field(default=0.25, ge=0.0)
    sensitive_data: float = Field(default=0.20, ge=0.0)
    toxicity: float = Field(default=0.15, ge=0.0)

    @model_validator(mode="after")
    def _nonzero(self) -> "RiskWeights":
        if self.prompt_injection + self.jailbreak + self.sensitive_data + self.toxicity <= 0:
            raise ValueError("risk weights must not all be zero")
        return self


class RiskPolicy(_Strict):
    weights: RiskWeights = Field(default_factory=RiskWeights)
    block_threshold: float = Field(default=0.85, ge=0.1, le=1.0)
    verify_threshold: float = Field(default=0.6, ge=0.05, le=1.0)
    critical_override: bool = True
    critical_floor: float = Field(default=0.95, ge=0.5, le=1.0)

    @model_validator(mode="after")
    def _order(self) -> "RiskPolicy":
        if self.verify_threshold > self.block_threshold:
            raise ValueError("verify_threshold must be <= block_threshold")
        return self


class VerificationPolicy(_Strict):
    enabled: bool = True
    provider: str = "ollama"
    model: str | None = None
    escalate_only: Literal[True] = True
    min_confidence_to_escalate: float = Field(default=0.7, ge=0.0, le=1.0)
    on_unavailable: Decision = Decision.HUMAN_REVIEW
    timeout_seconds: float = Field(default=30.0, gt=0, le=300)

    @field_validator("on_unavailable")
    @classmethod
    def _no_allow(cls, v: Decision) -> Decision:
        if v in (Decision.VERIFY, Decision.REDACT):
            raise ValueError("on_unavailable must be ALLOW, HUMAN_REVIEW or BLOCK")
        return v


class ProviderPolicy(_Strict):
    allowed_providers: list[str] = Field(default_factory=lambda: ["ollama", "openai_compatible"])
    cloud_requires_pii_redaction: bool = True
    cloud_block_secrets: bool = True
    allow_cloud_fallback: bool = False
    max_output_tokens: int = Field(default=1024, ge=16, le=16384)
    temperature: float = Field(default=0.2, ge=0.0, le=2.0)


class OutputPolicy(_Strict):
    enabled: bool = True
    pii_action: Decision = Decision.REDACT
    secret_action: Decision = Decision.BLOCK
    toxicity_threshold: float = Field(default=0.85, ge=0.05, le=1.0)
    toxicity_action: Decision = Decision.BLOCK
    unsafe_html_action: Decision = Decision.REDACT
    system_prompt_leak_action: Decision = Decision.BLOCK
    invalid_structure_action: Decision = Decision.BLOCK
    blocked_patterns: list[CustomPattern] = Field(default_factory=list, max_length=100)
    blocked_pattern_action: Decision = Decision.BLOCK
    grounding_min_support: float = Field(default=0.0, ge=0.0, le=1.0)
    grounding_action: Decision = Decision.ALLOW
    injection_echo_threshold: float = Field(default=0.9, ge=0.05, le=1.0)

    @model_validator(mode="after")
    def _output_actions(self) -> "OutputPolicy":
        allowed = {Decision.ALLOW, Decision.REDACT, Decision.BLOCK}
        for name in ("pii_action", "secret_action", "toxicity_action", "unsafe_html_action",
                     "system_prompt_leak_action", "invalid_structure_action", "blocked_pattern_action", "grounding_action"):
            if getattr(self, name) not in allowed:
                raise ValueError(f"output.{name} must be ALLOW, REDACT or BLOCK")
        if self.secret_action == Decision.ALLOW:
            raise ValueError("output.secret_action cannot be ALLOW")
        return self


class ContextPolicy(_Strict):
    enabled: bool = True
    threshold: float = Field(default=0.6, ge=0.05, le=1.0)
    mode: Mode = "hybrid"
    chunk_action: Literal["DROP", "SANITIZE", "FLAG"] = "DROP"
    block_request_if_flagged: bool = False
    max_chunks: int = Field(default=20, ge=1, le=200)
    max_chunk_chars: int = Field(default=20000, ge=100, le=200000)
    scan_pii: bool = True


class ArgSpec(_Strict):
    type: Literal["string", "integer", "number", "boolean", "enum"]
    required: bool = True
    max_length: int | None = Field(default=None, ge=1, le=100000)
    pattern: str | None = Field(default=None, max_length=300)
    enum: list[str] | None = None
    minimum: float | None = None
    maximum: float | None = None

    @field_validator("pattern")
    @classmethod
    def _compiles(cls, v: str | None) -> str | None:
        if v is not None:
            re.compile(v)
        return v


class ToolSpec(_Strict):
    description: str = ""
    enabled: bool = True
    permission: Literal["read", "write"] = "read"
    args: dict[str, ArgSpec] = Field(default_factory=dict)
    requires_approval: bool = False
    timeout_seconds: float = Field(default=5.0, gt=0, le=60)
    max_calls_per_session: int = Field(default=20, ge=0, le=10000)
    allowed_scopes: list[str] = Field(default_factory=lambda: ["default"])


class ToolsPolicy(_Strict):
    enabled: bool = True
    default_deny: Literal[True] = True
    scan_arguments: bool = True
    tools: dict[str, ToolSpec] = Field(default_factory=dict)


class ContextProfile(_Strict):
    description: str = ""
    weight_overrides: dict[str, float] = Field(default_factory=dict)
    threshold_multipliers: dict[str, float] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _bounds(self) -> "ContextProfile":
        valid = {"prompt_injection", "jailbreak", "sensitive_data", "toxicity"}
        for k, v in self.weight_overrides.items():
            if k not in valid or v < 0:
                raise ValueError(f"invalid weight override {k}={v}")
        for k, v in self.threshold_multipliers.items():
            if k not in {"prompt_injection", "jailbreak", "toxicity", "context"}:
                raise ValueError(f"invalid threshold multiplier key {k}")
            if not 0.8 <= v <= 1.5:
                raise ValueError("threshold multipliers must be within [0.8, 1.5]")
        return self


class SentinelPolicy(_Strict):
    version: int = 1
    prompt_injection: DetectorPolicy = Field(default_factory=lambda: DetectorPolicy(threshold=0.8, verify_band=(0.5, 0.8)))
    jailbreak: DetectorPolicy = Field(default_factory=lambda: DetectorPolicy(threshold=0.8, verify_band=(0.5, 0.8)))
    pii: PIIPolicy = Field(default_factory=PIIPolicy)
    secret_detection: SecretPolicy = Field(default_factory=SecretPolicy)
    toxicity: ToxicityPolicy = Field(default_factory=ToxicityPolicy)
    risk: RiskPolicy = Field(default_factory=RiskPolicy)
    verification: VerificationPolicy = Field(default_factory=VerificationPolicy)
    providers: ProviderPolicy = Field(default_factory=ProviderPolicy)
    output: OutputPolicy = Field(default_factory=OutputPolicy)
    context: ContextPolicy = Field(default_factory=ContextPolicy)
    tools: ToolsPolicy = Field(default_factory=ToolsPolicy)
    context_profiles: dict[str, ContextProfile] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _invariants(self) -> "SentinelPolicy":
        for name in ("prompt_injection", "jailbreak"):
            det: DetectorPolicy = getattr(self, name)
            if det.action == Decision.VERIFY:
                raise ValueError(f"{name}.action cannot be VERIFY: verification is escalate-only")
            if det.on_error not in _CRITICAL_ON_ERROR:
                raise ValueError(f"{name}.on_error must be BLOCK or HUMAN_REVIEW (fail closed)")
        if self.secret_detection.on_error not in _CRITICAL_ON_ERROR:
            raise ValueError("secret_detection.on_error must be BLOCK or HUMAN_REVIEW (fail closed)")
        if self.pii.on_error not in _CRITICAL_ON_ERROR:
            raise ValueError("pii.on_error must be BLOCK or HUMAN_REVIEW (fail closed)")
        if self.pii.action == Decision.VERIFY:
            raise ValueError("pii.action cannot be VERIFY")
        return self


# Sections that can be updated individually through PUT /api/v1/policies/{policy_id}
POLICY_SECTIONS: tuple[str, ...] = (
    "prompt_injection", "jailbreak", "pii", "secret_detection", "toxicity", "risk",
    "verification", "providers", "output", "context", "tools", "context_profiles",
)
