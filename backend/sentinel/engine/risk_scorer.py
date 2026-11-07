"""Module G - Risk scoring engine.

    R_weighted = (wP*P + wJ*J + wS*S + wT*T) / (wP + wJ + wS + wT)

with P = prompt-injection score, J = jailbreak score, S = sensitive-data score
(max of PII and secret scores), T = toxicity score. Weights come from policy
and may be overridden by an application context profile.

Averaging must never hide a confirmed critical finding, so when
``critical_override`` is on:

    R = max(R_weighted, s_i for every *detected* injection/jailbreak/secret finding,
            critical_floor if any finding has CRITICAL severity)

PII and toxicity contribute only through the weighted sum; they have their own
deterministic REDACT/VERIFY handling in the policy engine.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from sentinel.engine.policy_schema import SentinelPolicy
from sentinel.schemas.common import DetectionResult, DetectorStatus, Severity, severity_from_score

COMPONENTS = ("prompt_injection", "jailbreak", "sensitive_data", "toxicity")
_GUARDED = ("prompt_injection", "jailbreak", "secret_detection")


class RiskComponent(BaseModel):
    score: float
    weight: float
    contribution: float
    sources: list[str] = Field(default_factory=list)
    status: str = "ok"


class RiskAssessment(BaseModel):
    score: float
    weighted_score: float
    severity: Severity
    components: dict[str, RiskComponent]
    critical_override: bool = False
    override_reasons: list[str] = Field(default_factory=list)
    incomplete: bool = False
    failed_detectors: list[str] = Field(default_factory=list)
    profile: str | None = None
    explanation: list[str] = Field(default_factory=list)


def effective_weights(policy: SentinelPolicy, profile: str | None) -> dict[str, float]:
    w = policy.risk.weights.model_dump()
    if profile and profile in policy.context_profiles:
        w.update(policy.context_profiles[profile].weight_overrides)
    return w


def score_risk(results: dict[str, DetectionResult], policy: SentinelPolicy, profile: str | None = None) -> RiskAssessment:
    weights = effective_weights(policy, profile)

    def comp_score(*names: str) -> tuple[float, list[str], str]:
        vals, srcs, status = [], [], "ok"
        for n in names:
            r = results.get(n)
            if r is None or r.status == DetectorStatus.DISABLED:
                continue
            if r.failed:
                status = "failed"
                continue
            if r.status == DetectorStatus.DEGRADED and status == "ok":
                status = "degraded"
            vals.append(r.score)
            srcs.append(n)
        return (max(vals) if vals else 0.0), srcs, status

    raw = {
        "prompt_injection": comp_score("prompt_injection"),
        "jailbreak": comp_score("jailbreak"),
        "sensitive_data": comp_score("pii", "secret_detection"),
        "toxicity": comp_score("toxicity"),
    }
    total_w = sum(weights[c] for c in COMPONENTS) or 1.0
    components: dict[str, RiskComponent] = {}
    weighted = 0.0
    for c in COMPONENTS:
        s, srcs, status = raw[c]
        w = weights[c] / total_w
        contrib = s * w
        weighted += contrib
        components[c] = RiskComponent(score=round(s, 4), weight=round(w, 4), contribution=round(contrib, 4), sources=srcs, status=status)

    final = weighted
    reasons: list[str] = []
    if policy.risk.critical_override:
        for name in _GUARDED:
            r = results.get(name)
            if r is not None and r.detected and not r.failed and r.score > final:
                final = r.score
                reasons.append(f"{name} finding (score {r.score:.2f}) overrides the weighted average")
        crit = [n for n, r in results.items() if r.severity == Severity.CRITICAL and not r.failed]
        if crit and final < policy.risk.critical_floor:
            final = policy.risk.critical_floor
            reasons.append(f"critical severity from {', '.join(sorted(crit))} raises risk to floor {policy.risk.critical_floor}")

    failed = sorted(n for n, r in results.items() if r.failed)
    explanation = [
        f"{c}: score {components[c].score:.2f} x weight {components[c].weight:.2f} = {components[c].contribution:.3f}"
        for c in COMPONENTS
        if components[c].score > 0
    ]
    explanation.append(f"weighted risk {weighted:.3f}")
    explanation.extend(reasons)
    if failed:
        explanation.append(f"incomplete assessment: {', '.join(failed)} failed")

    severity = severity_from_score(final)
    if any(r.severity == Severity.CRITICAL for r in results.values() if not r.failed):
        severity = Severity.CRITICAL

    return RiskAssessment(
        score=round(min(1.0, final), 4),
        weighted_score=round(weighted, 4),
        severity=severity,
        components=components,
        critical_override=bool(reasons),
        override_reasons=reasons,
        incomplete=bool(failed),
        failed_detectors=failed,
        profile=profile,
        explanation=explanation,
    )
