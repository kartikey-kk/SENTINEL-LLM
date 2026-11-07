"""SQLAlchemy ORM models.

Privacy rules enforced by the schema itself:
* No column stores raw prompts unless ``SENTINEL_AUDIT_STORE_RAW_PROMPTS`` is on
  (then ``raw_input`` is populated; it is off by default).
* ``input_fingerprint`` is an HMAC, not a plain hash, so short prompts cannot be
  brute-forced from the database.
* ``model_providers.api_key_env`` stores the *name* of an environment variable,
  never a key.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSON, list[Any]: JSON}


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    request_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    session_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    event_type: Mapped[str] = mapped_column(String(32), index=True)  # input|output|context|tool|chat
    threat_category: Mapped[str] = mapped_column(String(64), index=True, default="none")
    threat_categories: Mapped[list[Any]] = mapped_column(JSON, default=list)
    severity: Mapped[str] = mapped_column(String(16), index=True, default="none")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    decision: Mapped[str] = mapped_column(String(16), index=True)
    output_decision: Mapped[str | None] = mapped_column(String(16), nullable=True)
    provider: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    detector_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    processing_latency: Mapped[float] = mapped_column(Float, default=0.0)  # milliseconds
    input_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    input_preview: Mapped[str | None] = mapped_column(Text, nullable=True)  # redacted + truncated
    raw_input: Mapped[str | None] = mapped_column(Text, nullable=True)  # only if explicitly enabled
    policy_version: Mapped[int] = mapped_column(Integer, default=1)
    review_status: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    client_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    detections: Mapped[list[DetectionResultRow]] = relationship(
        back_populates="event", cascade="all, delete-orphan", lazy="selectin"
    )


class DetectionResultRow(Base):
    __tablename__ = "detection_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("security_events.id", ondelete="CASCADE"), index=True)
    stage: Mapped[str] = mapped_column(String(16))  # input|output|context|tool
    detector: Mapped[str] = mapped_column(String(64), index=True)
    detected: Mapped[bool] = mapped_column(Boolean, default=False)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="none")
    status: Mapped[str] = mapped_column(String(16), default="ok")
    method: Mapped[str] = mapped_column(String(32), default="rules")
    reason: Mapped[str] = mapped_column(Text, default="")
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # masked evidence, entity types

    event: Mapped[SecurityEvent] = relationship(back_populates="detections")


class PolicyRecord(Base):
    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    policy_id: Mapped[str] = mapped_column(String(64), index=True)
    version: Mapped[int] = mapped_column(Integer)
    document: Mapped[dict[str, Any]] = mapped_column(JSON)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    updated_by: Mapped[str] = mapped_column(String(64), default="system")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)


class ModelProvider(Base):
    __tablename__ = "model_providers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    provider_type: Mapped[str] = mapped_column(String(32))
    base_url: Mapped[str] = mapped_column(String(512))
    default_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    models: Mapped[list[Any]] = mapped_column(JSON, default=list)
    is_local: Mapped[bool] = mapped_column(Boolean, default=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    api_key_env: Mapped[str | None] = mapped_column(String(128), nullable=True)  # env var NAME only
    last_health: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    last_latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RequestMetric(Base):
    __tablename__ = "request_metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    request_id: Mapped[str] = mapped_column(String(64), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    endpoint: Mapped[str] = mapped_column(String(64))
    provider: Mapped[str | None] = mapped_column(String(64), nullable=True)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status_code: Mapped[int] = mapped_column(Integer, default=200)
    decision: Mapped[str | None] = mapped_column(String(16), nullable=True)
    total_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    detection_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    llm_latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[bool] = mapped_column(Boolean, default=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str | None] = mapped_column(String(128), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
