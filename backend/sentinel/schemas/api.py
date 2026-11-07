"""Public REST API request/response models."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from sentinel.detection.context_detector import ContextChunk, ContextInspection
from sentinel.detection.output_validator import GroundingReport, OutputCheck
from sentinel.detection.verifier import VerificationResult
from sentinel.engine.policy_engine import PolicyReason
from sentinel.engine.risk_scorer import RiskAssessment
from sentinel.schemas.common import Decision, DetectionResult, EntityInfo
from sentinel.security.tool_guard import ToolCallRequest, ToolDecision

MAX_TEXT = 1_000_000  # hard ceiling; SENTINEL_MAX_INPUT_CHARS enforces the configured limit


class _Req(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HistoryMessage(_Req):
    role: Literal["user", "assistant"]
    content: str = Field(max_length=MAX_TEXT)


class InspectInputRequest(_Req):
    text: str = Field(min_length=1, max_length=MAX_TEXT)
    content_type: Literal["text", "json"] = "text"
    session_id: str | None = Field(default=None, max_length=128)
    context_profile: str | None = Field(default=None, max_length=64)
    provider: str | None = Field(default=None, max_length=64, description="Intended destination provider (affects cloud privacy rules)")
    history: list[HistoryMessage] = Field(default_factory=list, max_length=50)
    detection_mode: Literal["rules", "ml", "hybrid"] | None = Field(
        default=None, description="Admin-only override used for experiments"
    )
    verify: bool = Field(default=True, description="Allow selective LLM verification for uncertain scores")


class NormalizationInfo(BaseModel):
    signals: list[dict[str, Any]] = Field(default_factory=list)
    removed_chars: int = 0
    decoded_views: list[str] = Field(default_factory=list)


class PolicyInfo(BaseModel):
    version: int
    reasons: list[PolicyReason]
    initial_decision: Decision


class InspectInputResponse(BaseModel):
    request_id: str
    decision: Decision
    forwardable: bool
    risk: RiskAssessment
    detections: list[DetectionResult]
    policy: PolicyInfo
    sanitized_text: str
    redactions: list[EntityInfo]
    normalization: NormalizationInfo
    verification: VerificationResult | None = None
    message: str | None = None
    latency_ms: float


class InspectOutputRequest(_Req):
    text: str = Field(min_length=1, max_length=MAX_TEXT)
    system_prompt: str | None = Field(default=None, max_length=50_000)
    canary: str | None = Field(default=None, max_length=128)
    response_format: Literal["text", "json"] = "text"
    json_schema: dict[str, Any] | None = None
    evidence: list[str] | None = Field(default=None, max_length=50)
    session_id: str | None = Field(default=None, max_length=128)


class InspectOutputResponse(BaseModel):
    request_id: str
    decision: Decision
    checks: list[OutputCheck]
    detections: list[DetectionResult]
    sanitized_text: str | None
    redactions: list[EntityInfo]
    grounding: GroundingReport | None = None
    latency_ms: float


class InspectContextRequest(_Req):
    chunks: list[ContextChunk] = Field(min_length=1, max_length=200)
    provider: str | None = Field(default=None, max_length=64)
    session_id: str | None = Field(default=None, max_length=128)
    context_profile: str | None = Field(default=None, max_length=64)


class InspectContextResponse(ContextInspection):
    request_id: str
    latency_ms: float


class InspectToolRequest(ToolCallRequest):
    model_config = ConfigDict(extra="forbid")


class InspectToolResponse(ToolDecision):
    request_id: str
    output_inspection: ContextInspection | None = None
    latency_ms: float


class ToolApprovalRequest(_Req):
    tool_name: str = Field(min_length=1, max_length=64)
    arguments: dict[str, Any] = Field(default_factory=dict)
    session_id: str = Field(min_length=1, max_length=128)


class ChatRequest(_Req):
    message: str = Field(min_length=1, max_length=MAX_TEXT)
    history: list[HistoryMessage] = Field(default_factory=list, max_length=50)
    system_prompt: str | None = Field(default=None, max_length=50_000)
    context: list[ContextChunk] = Field(default_factory=list, max_length=50)
    provider: str | None = Field(default=None, max_length=64)
    model: str | None = Field(default=None, max_length=128)
    session_id: str | None = Field(default=None, max_length=128)
    context_profile: str | None = Field(default=None, max_length=64)
    response_format: Literal["text", "json"] = "text"
    json_schema: dict[str, Any] | None = None
    evidence: list[str] | None = Field(default=None, max_length=50)
    restore_pii: bool = False
    temperature: float = Field(default=0.2, ge=0.0, le=2.0)
    max_tokens: int = Field(default=512, ge=1, le=16384)


class StageSummary(BaseModel):
    decision: Decision
    risk: float | None = None
    detections: list[DetectionResult] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    redactions: list[EntityInfo] = Field(default_factory=list)


class ChatSecurity(BaseModel):
    decision: Decision
    input: StageSummary
    context: ContextInspection | None = None
    output: StageSummary | None = None
    output_checks: list[OutputCheck] = Field(default_factory=list)
    risk: RiskAssessment | None = None
    verification: VerificationResult | None = None
    sanitized_prompt: str | None = None
    restored_placeholders: int = 0
    fallback_used: bool = False


class ChatUsage(BaseModel):
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    llm_latency_ms: float | None = None


class ChatResponse(BaseModel):
    request_id: str
    text: str
    blocked: bool
    provider: str | None
    model: str | None
    security: ChatSecurity
    usage: ChatUsage
    latency_ms: float


class EventDetection(BaseModel):
    stage: str
    detector: str
    detected: bool
    score: float
    confidence: float | None
    severity: str
    status: str
    method: str
    reason: str
    latency_ms: float
    details: dict[str, Any]


class EventOut(BaseModel):
    request_id: str
    timestamp: datetime
    session_id: str | None
    event_type: str
    threat_category: str
    threat_categories: list[str]
    severity: str
    risk_score: float
    decision: str
    output_decision: str | None
    provider: str | None
    model: str | None
    processing_latency: float
    input_preview: str | None
    policy_version: int
    review_status: str | None


class EventDetailOut(EventOut):
    detector_metadata: dict[str, Any]
    detections: list[EventDetection]


class EventPage(BaseModel):
    items: list[EventOut]
    total: int
    limit: int
    offset: int


class ReviewRequest(_Req):
    status: Literal["approved", "rejected", "false_positive", "true_positive"]
    note: str | None = Field(default=None, max_length=1000)


class PolicyUpdateRequest(_Req):
    value: Any
    comment: str | None = Field(default=None, max_length=500)
