"""Audit and analytics persistence.

Every security decision produces a ``security_events`` row plus one
``detection_results`` row per detector run. What is stored:

* decision, risk, severity, threat categories, latency, policy version
* per-detector scores/status/method/reason and *sanitized* evidence
  (rule ids, entity-type counts, masked secret previews - never raw values)
* an HMAC fingerprint of the input (for de-duplication without storing it)
* optionally a redacted, truncated preview (``SENTINEL_AUDIT_STORE_REDACTED_PREVIEW``)
* the raw input only if ``SENTINEL_AUDIT_STORE_RAW_PROMPTS=true`` (off by default)

Rows older than ``SENTINEL_AUDIT_RETENTION_DAYS`` are purged periodically.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, select

from sentinel.config import Settings
from sentinel.db.models import AuditLog, DetectionResultRow, RequestMetric, SecurityEvent
from sentinel.db.session import Database
from sentinel.schemas.common import SEVERITY_RANK, DetectionResult, Severity

logger = logging.getLogger(__name__)

CATEGORY_NAMES = {
    "prompt_injection": "prompt_injection",
    "jailbreak": "jailbreak",
    "pii": "pii",
    "secret_detection": "secret",
    "toxicity": "toxicity",
    "context": "indirect_injection",
    "tool": "tool_abuse",
    "tool_guard": "tool_abuse",
}
# Stages whose detection rows are keyed by item (chunk id, tool name) rather than detector name.
STAGE_CATEGORY = {"context": "indirect_injection", "tool": "tool_abuse"}


def category_for(stage: str, name: str) -> str:
    if stage in STAGE_CATEGORY:
        return STAGE_CATEGORY[stage]
    base = CATEGORY_NAMES.get(name, name)
    return f"output_{base}" if stage == "output" else base


class AuditError(RuntimeError):
    pass


def sanitize_detection(r: DetectionResult) -> dict[str, Any]:
    """Strip anything that could carry raw user content from detector metadata."""
    md = r.metadata or {}
    details: dict[str, Any] = {"evidence": r.evidence[:10]}
    if "matches" in md:
        details["rules"] = [{"rule": m.get("rule"), "category": m.get("category"), "rule_weight": m.get("rule_weight"),
                             "view": m.get("view")} for m in md["matches"]]
    for key in ("rule_score", "rule_categories", "ml_available", "obfuscated", "multi_turn_score", "multi_turn_indicators",
                "entity_counts", "secret_counts", "ignored_placeholders", "engine", "classification", "mode"):
        if key in md:
            details[key] = md[key]
    if "ml" in md and isinstance(md["ml"], dict):
        details["ml"] = {k: md["ml"][k] for k in ("label", "probs", "chunks", "decoded_prob") if k in md["ml"]}
    if "probabilities" in md:
        details["probabilities"] = md["probabilities"]
    if r.entities:
        details["entities"] = [{"type": e.type, "start": e.start, "end": e.end, "score": e.score} for e in r.entities[:50]]
    return details


class AuditService:
    def __init__(self, db: Database, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self._key = settings.effective_secret_key()

    def fingerprint(self, text: str) -> str:
        return hmac.new(self._key, text.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:32]

    def preview(self, sanitized_text: str | None) -> str | None:
        if not sanitized_text or not self.settings.audit_store_redacted_preview:
            return None
        n = self.settings.audit_preview_chars
        return sanitized_text if len(sanitized_text) <= n else sanitized_text[:n] + "…"

    def client_id(self, api_key: str | None) -> str | None:
        if not api_key:
            return None
        return "key_" + hmac.new(self._key, b"client:" + api_key.encode(), hashlib.sha256).hexdigest()[:12]

    async def record_event(
        self,
        *,
        request_id: str,
        event_type: str,
        decision: str,
        stages: dict[str, dict[str, DetectionResult]],
        risk_score: float = 0.0,
        severity: Severity | None = None,
        output_decision: str | None = None,
        session_id: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        latency_ms: float = 0.0,
        raw_input: str | None = None,
        sanitized_preview: str | None = None,
        policy_version: int = 1,
        client_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        extra_categories: list[str] | None = None,
        review_status: str | None = None,
    ) -> None:
        detected: list[tuple[float, str]] = []
        max_sev = severity or Severity.NONE
        rows: list[DetectionResultRow] = []
        for stage, results in stages.items():
            for name, r in results.items():
                if r.detected:
                    detected.append((r.score, category_for(stage, name)))
                    if SEVERITY_RANK[r.severity] > SEVERITY_RANK[max_sev]:
                        max_sev = r.severity
                rows.append(DetectionResultRow(
                    stage=stage, detector=name, detected=r.detected, score=r.score, confidence=r.confidence,
                    severity=r.severity.value, status=r.status.value, method=r.method, reason=r.reason[:500],
                    latency_ms=r.latency_ms, details=sanitize_detection(r),
                ))
        categories = [c for _, c in sorted(detected, reverse=True)]
        for c in extra_categories or []:
            if c not in categories:
                categories.append(c)
        event = SecurityEvent(
            request_id=request_id,
            session_id=session_id,
            event_type=event_type,
            threat_category=categories[0] if categories else "none",
            threat_categories=categories,
            severity=max_sev.value,
            risk_score=round(risk_score, 4),
            decision=decision,
            output_decision=output_decision,
            provider=provider,
            model=model,
            detector_metadata=metadata or {},
            processing_latency=round(latency_ms, 2),
            input_fingerprint=self.fingerprint(raw_input) if raw_input else None,
            input_preview=self.preview(sanitized_preview),
            raw_input=raw_input if (raw_input and self.settings.audit_store_raw_prompts) else None,
            policy_version=policy_version,
            client_id=client_id,
            review_status=review_status or ("pending" if decision == "HUMAN_REVIEW" else None),
        )
        event.detections = rows
        try:
            async with self.db.sessionmaker() as s:
                s.add(event)
                await s.commit()
        except Exception as exc:
            logger.error("Audit write failed for %s: %s", request_id, type(exc).__name__)
            if self.settings.audit_fail_closed:
                raise AuditError("audit log unavailable") from None

    async def record_metric(self, **fields: Any) -> None:
        try:
            async with self.db.sessionmaker() as s:
                s.add(RequestMetric(**fields))
                await s.commit()
        except Exception as exc:  # metrics are best-effort
            logger.warning("Metric write failed: %s", type(exc).__name__)

    async def log(self, actor: str, action: str, *, target: str | None = None, request_id: str | None = None,
                  details: dict[str, Any] | None = None) -> None:
        try:
            async with self.db.sessionmaker() as s:
                s.add(AuditLog(actor=actor, action=action, target=target, request_id=request_id, details=details or {}))
                await s.commit()
        except Exception as exc:
            logger.error("Audit log write failed: %s", type(exc).__name__)
            if self.settings.audit_fail_closed:
                raise AuditError("audit log unavailable") from None

    async def purge_expired(self) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.settings.audit_retention_days)
        async with self.db.sessionmaker() as s:
            ev = await s.execute(delete(SecurityEvent).where(SecurityEvent.timestamp < cutoff))
            await s.execute(delete(DetectionResultRow).where(~DetectionResultRow.event_id.in_(select(SecurityEvent.id))))
            await s.execute(delete(RequestMetric).where(RequestMetric.timestamp < cutoff))
            await s.commit()
            purged = int(getattr(ev, "rowcount", 0) or 0)
        if purged:
            await self.log("system", "retention.purge", details={"events": purged, "cutoff": cutoff.isoformat()})
        return purged
