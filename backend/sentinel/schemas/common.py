"""Shared enums and result models used across detection, policy and API layers."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr


class Severity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.NONE: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def max_severity(*values: Severity) -> Severity:
    return max(values, key=lambda s: SEVERITY_RANK[s], default=Severity.NONE)


def severity_from_score(score: float) -> Severity:
    """Map a normalized 0..1 risk score onto a severity bucket."""
    if score >= 0.9:
        return Severity.HIGH
    if score >= 0.7:
        return Severity.MEDIUM
    if score >= 0.4:
        return Severity.LOW
    return Severity.NONE


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    VERIFY = "VERIFY"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    BLOCK = "BLOCK"


DECISION_PRECEDENCE: dict[Decision, int] = {
    Decision.ALLOW: 0,
    Decision.REDACT: 1,
    Decision.VERIFY: 2,
    Decision.HUMAN_REVIEW: 3,
    Decision.BLOCK: 4,
}


def most_restrictive(*decisions: Decision) -> Decision:
    return max(decisions, key=lambda d: DECISION_PRECEDENCE[d], default=Decision.ALLOW)


class DetectorStatus(str, Enum):
    OK = "ok"
    DEGRADED = "degraded"  # ran, but an optional component (e.g. ML model) was unavailable
    ERROR = "error"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    DISABLED = "disabled"


FAILED_STATUSES = {DetectorStatus.ERROR, DetectorStatus.TIMEOUT, DetectorStatus.UNAVAILABLE}


class EntityInfo(BaseModel):
    """A sensitive span found in text. Never carries the raw value."""

    type: str
    start: int
    end: int
    score: float
    recognizer: str
    placeholder: str | None = None


class SensitiveSpan(BaseModel):
    """Internal-only span that includes the matched text. Never serialized to clients."""

    model_config = ConfigDict(frozen=True)

    type: str
    start: int
    end: int
    score: float
    recognizer: str
    value: str
    category: str  # "pii" or "secret"

    def public(self, placeholder: str | None = None) -> EntityInfo:
        return EntityInfo(
            type=self.type,
            start=self.start,
            end=self.end,
            score=round(self.score, 4),
            recognizer=self.recognizer,
            placeholder=placeholder,
        )


class DetectionResult(BaseModel):
    """Structured output of a single detector.

    * ``score`` is the normalized 0..1 risk used by the risk engine.
    * ``confidence`` is a model probability and is ``None`` when the detector
      did not use a probabilistic model (pure rule hits are reported via
      ``rule_weight`` in metadata, never disguised as probabilities).
    """

    detector: str
    detected: bool = False
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    severity: Severity = Severity.NONE
    reason: str = ""
    evidence: list[str] = Field(default_factory=list)
    method: str = "rules"
    status: DetectorStatus = DetectorStatus.OK
    latency_ms: float = 0.0
    entities: list[EntityInfo] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    _spans: list[SensitiveSpan] = PrivateAttr(default_factory=list)

    @property
    def spans(self) -> list[SensitiveSpan]:
        return self._spans

    def set_spans(self, spans: list[SensitiveSpan]) -> None:
        self._spans = list(spans)
        self.entities = [s.public() for s in spans]

    @property
    def failed(self) -> bool:
        return self.status in FAILED_STATUSES
