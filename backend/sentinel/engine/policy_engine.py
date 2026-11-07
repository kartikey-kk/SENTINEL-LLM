"""Module H - Policy engine and policy store.

The policy engine turns detector results + risk assessment into a decision.
It never calls detectors or providers and never mutates text: enforcement is
a separate layer (``engine/enforcement.py``).

Decision precedence: BLOCK > HUMAN_REVIEW > VERIFY > REDACT > ALLOW.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.db.models import AuditLog, PolicyRecord
from sentinel.engine.policy_schema import POLICY_SECTIONS, DetectorPolicy, SentinelPolicy
from sentinel.engine.risk_scorer import RiskAssessment
from sentinel.schemas.common import Decision, DetectionResult, DetectorStatus, most_restrictive

logger = logging.getLogger(__name__)


class PolicyValidationError(ValueError):
    def __init__(self, errors: list[dict[str, Any]]):
        super().__init__("policy validation failed")
        self.errors = errors


class ProviderContext(BaseModel):
    name: str | None = None
    is_local: bool | None = None


class PolicyReason(BaseModel):
    source: str
    action: Decision
    rule: str
    detail: str = ""


class PolicyDecision(BaseModel):
    decision: Decision
    reasons: list[PolicyReason] = Field(default_factory=list)
    redact_categories: list[str] = Field(default_factory=list)  # "pii", "secret"
    verify_sources: list[str] = Field(default_factory=list)
    policy_version: int = 1

    def decision_without_verify(self) -> Decision:
        """Decision that applies if escalate-only verification finds nothing."""
        return most_restrictive(*(r.action for r in self.reasons if r.action != Decision.VERIFY))

    @property
    def summary(self) -> list[str]:
        return [f"{r.source}: {r.action.value} ({r.rule})" for r in self.reasons if r.action != Decision.ALLOW]


def effective_threshold(policy: SentinelPolicy, detector: str, profile: str | None) -> float:
    base = {
        "prompt_injection": policy.prompt_injection.threshold,
        "jailbreak": policy.jailbreak.threshold,
        "toxicity": policy.toxicity.threshold,
        "context": policy.context.threshold,
    }.get(detector, 0.5)
    if profile and profile in policy.context_profiles:
        mult = policy.context_profiles[profile].threshold_multipliers.get(detector, 1.0)
        return round(min(0.99, base * mult), 4)
    return base


def effective_band(det: DetectorPolicy, threshold: float) -> tuple[float, float] | None:
    if det.verify_band is None:
        return None
    lo, _ = det.verify_band
    return (lo, threshold)


class PolicyEngine:
    """Stateless evaluator: (results, risk, policy, provider) -> PolicyDecision."""

    def evaluate(
        self,
        results: dict[str, DetectionResult],
        risk: RiskAssessment,
        policy: SentinelPolicy,
        *,
        provider: ProviderContext | None = None,
        profile: str | None = None,
    ) -> PolicyDecision:
        reasons: list[PolicyReason] = []
        redact: set[str] = set()
        verify: list[str] = []
        is_cloud = provider is not None and provider.is_local is False

        def failure(name: str, r: DetectionResult, on_error: Decision) -> None:
            reasons.append(PolicyReason(source=name, action=on_error, rule="detector_failure",
                                        detail=f"{name} status={r.status.value}; policy on_error={on_error.value}"))

        # --- classifier-style detectors -------------------------------------
        for name in ("prompt_injection", "jailbreak"):
            det: DetectorPolicy = getattr(policy, name)
            r = results.get(name)
            if not det.enabled or r is None or r.status == DetectorStatus.DISABLED:
                continue
            if r.failed:
                failure(name, r, det.on_error)
                continue
            thr = effective_threshold(policy, name, profile)
            if r.score >= thr:
                reasons.append(PolicyReason(source=name, action=det.action, rule="threshold",
                                            detail=f"score {r.score:.2f} >= threshold {thr:.2f}"))
            else:
                band = effective_band(det, thr)
                if band and band[0] <= r.score < band[1] and policy.verification.enabled:
                    reasons.append(PolicyReason(source=name, action=Decision.VERIFY, rule="uncertainty_band",
                                                detail=f"score {r.score:.2f} in [{band[0]:.2f}, {band[1]:.2f})"))
                    verify.append(name)
            if r.status == DetectorStatus.DEGRADED:
                reasons.append(PolicyReason(source=name, action=Decision.ALLOW, rule="degraded",
                                            detail="ML component unavailable; rules-only result"))

        tox = results.get("toxicity")
        if policy.toxicity.enabled and tox is not None and tox.status != DetectorStatus.DISABLED:
            if tox.failed:
                failure("toxicity", tox, policy.toxicity.on_error)
            else:
                thr = effective_threshold(policy, "toxicity", profile)
                if tox.score >= thr:
                    action = policy.toxicity.action
                    if action == Decision.VERIFY and not policy.verification.enabled:
                        action = policy.verification.on_unavailable
                    reasons.append(PolicyReason(source="toxicity", action=action, rule="threshold",
                                                detail=f"score {tox.score:.2f} >= threshold {thr:.2f}"))
                    if action == Decision.VERIFY:
                        verify.append("toxicity")

        # --- deterministic sensitive-data handling ---------------------------
        pii = results.get("pii")
        if policy.pii.enabled and pii is not None and pii.status != DetectorStatus.DISABLED:
            if pii.failed:
                failure("pii", pii, policy.pii.on_error)
            elif pii.detected:
                types = {e.type for e in pii.entities}
                blocked = types & set(policy.pii.block_entities)
                if blocked:
                    reasons.append(PolicyReason(source="pii", action=Decision.BLOCK, rule="block_entities",
                                                detail=f"blocked entity types: {', '.join(sorted(blocked))}"))
                action = policy.pii.action
                if is_cloud and policy.providers.cloud_requires_pii_redaction and action == Decision.ALLOW:
                    action = Decision.REDACT
                    reasons.append(PolicyReason(source="pii", action=action, rule="cloud_requires_redaction",
                                                detail=f"provider {provider.name if provider else ''} is not local"))
                else:
                    reasons.append(PolicyReason(source="pii", action=action, rule="pii_detected",
                                                detail=", ".join(sorted(types))))
                if action == Decision.REDACT:
                    redact.add("pii")

        sec = results.get("secret_detection")
        if policy.secret_detection.enabled and sec is not None and sec.status != DetectorStatus.DISABLED:
            if sec.failed:
                failure("secret_detection", sec, policy.secret_detection.on_error)
            elif sec.detected:
                action = policy.secret_detection.action
                if is_cloud and policy.providers.cloud_block_secrets:
                    action = Decision.BLOCK
                reasons.append(PolicyReason(source="secret_detection", action=action, rule="secret_detected",
                                            detail=", ".join(sorted({e.type for e in sec.entities}))))
                if action == Decision.REDACT:
                    redact.add("secret")

        # --- aggregate risk --------------------------------------------------
        if risk.score >= policy.risk.block_threshold:
            reasons.append(PolicyReason(source="risk", action=Decision.BLOCK, rule="risk_block_threshold",
                                        detail=f"risk {risk.score:.2f} >= {policy.risk.block_threshold:.2f}"))
        elif risk.score >= policy.risk.verify_threshold and policy.verification.enabled:
            reasons.append(PolicyReason(source="risk", action=Decision.VERIFY, rule="risk_verify_threshold",
                                        detail=f"risk {risk.score:.2f} >= {policy.risk.verify_threshold:.2f}"))
            verify.append("risk")

        # --- provider permission ---------------------------------------------
        if provider is not None and provider.name is not None and provider.name not in policy.providers.allowed_providers:
            reasons.append(PolicyReason(source="providers", action=Decision.BLOCK, rule="provider_not_permitted",
                                        detail=f"provider {provider.name} not in allowed_providers"))

        decision = most_restrictive(*(r.action for r in reasons)) if reasons else Decision.ALLOW
        if decision == Decision.ALLOW and redact:
            decision = Decision.REDACT
        return PolicyDecision(
            decision=decision,
            reasons=reasons,
            redact_categories=sorted(redact),
            verify_sources=verify,
            policy_version=policy.version,
        )


# ---------------------------------------------------------------------------
# Policy store
# ---------------------------------------------------------------------------
def load_policy_file(path: Path) -> SentinelPolicy:
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return SentinelPolicy.model_validate(data)


def policy_hash(policy: SentinelPolicy) -> str:
    return hashlib.sha256(json.dumps(policy.model_dump(mode="json"), sort_keys=True).encode()).hexdigest()


class PolicyStore:
    """Holds the active policy snapshot. Requests read an immutable snapshot;
    updates validate a complete candidate policy and swap it atomically."""

    def __init__(self, policy: SentinelPolicy) -> None:
        self._policy = policy
        self._lock = asyncio.Lock()

    @classmethod
    def from_file(cls, path: Path) -> "PolicyStore":
        return cls(load_policy_file(path))

    @property
    def current(self) -> SentinelPolicy:
        return self._policy

    def snapshot(self) -> SentinelPolicy:
        return self._policy.model_copy(deep=True)

    def hash(self) -> str:
        return policy_hash(self._policy)

    def section(self, section: str) -> Any:
        if section not in POLICY_SECTIONS:
            raise KeyError(section)
        return copy.deepcopy(_dump_section(self._policy, section))

    def validate_candidate(self, section: str, document: Any) -> SentinelPolicy:
        if section not in POLICY_SECTIONS:
            raise KeyError(section)
        data = self._policy.model_dump(mode="json")
        data[section] = document
        data["version"] = self._policy.version + 1
        try:
            return SentinelPolicy.model_validate(data)
        except ValidationError as exc:
            errors = [{"loc": [str(x) for x in e["loc"]], "msg": e["msg"]} for e in exc.errors()]
            raise PolicyValidationError(errors) from None

    async def update_section(
        self, session: AsyncSession, section: str, document: Any, *, actor: str, comment: str | None = None
    ) -> SentinelPolicy:
        async with self._lock:
            candidate = self.validate_candidate(section, document)
            before = self.section(section)
            await session.execute(
                update(PolicyRecord).where(PolicyRecord.policy_id == section, PolicyRecord.is_active.is_(True)).values(is_active=False)
            )
            session.add(PolicyRecord(policy_id=section, version=candidate.version,
                                     document={"value": _dump_section(candidate, section)},
                                     is_active=True, updated_by=actor, comment=comment))
            session.add(AuditLog(actor=actor, action="policy.update", target=section,
                                 details={"from_version": self._policy.version, "to_version": candidate.version,
                                          "before": before, "after": _dump_section(candidate, section), "comment": comment}))
            await session.commit()
            self._policy = candidate
            logger.info("Policy section %s updated to version %d by %s", section, candidate.version, actor)
            return candidate

    async def load_overrides(self, session: AsyncSession) -> int:
        """Apply the latest active per-section records from the database on top of the YAML policy."""
        rows = (await session.execute(select(PolicyRecord).where(PolicyRecord.is_active.is_(True)))).scalars().all()
        if not rows:
            return 0
        data = self._policy.model_dump(mode="json")
        max_version = self._policy.version
        for row in rows:
            if row.policy_id in POLICY_SECTIONS:
                data[row.policy_id] = row.document.get("value")
                max_version = max(max_version, row.version)
        data["version"] = max_version
        try:
            self._policy = SentinelPolicy.model_validate(data)
        except ValidationError:
            logger.error("Stored policy overrides failed validation; keeping file policy")
            return 0
        return len(rows)


def _dump_section(policy: SentinelPolicy, section: str) -> Any:
    value = getattr(policy, section)
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {k: (v.model_dump(mode="json") if isinstance(v, BaseModel) else v) for k, v in value.items()}
    return value
