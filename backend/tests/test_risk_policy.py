"""Risk scoring, policy engine decisions and policy validation invariants."""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.engine.policy_engine import PolicyEngine, PolicyStore, PolicyValidationError, ProviderContext, load_policy_file
from sentinel.engine.policy_schema import SentinelPolicy
from sentinel.engine.risk_scorer import score_risk
from sentinel.schemas.common import Decision, DetectionResult, DetectorStatus, EntityInfo, Severity

POLICY_FILE = Path(__file__).resolve().parents[1] / "policies" / "default.yaml"


@pytest.fixture
def policy() -> SentinelPolicy:
    return load_policy_file(POLICY_FILE)


def res(name: str, score: float, *, detected: bool | None = None, severity=Severity.NONE, status=DetectorStatus.OK,
        entities: list[str] | None = None) -> DetectionResult:
    r = DetectionResult(detector=name, score=score, detected=score >= 0.8 if detected is None else detected,
                        severity=severity, status=status)
    if entities:
        r.entities = [EntityInfo(type=t, start=0, end=1, score=1.0, recognizer="t") for t in entities]
    return r


def test_weighted_formula_matches_spec(policy):
    results = {"prompt_injection": res("prompt_injection", 0.5, detected=False), "jailbreak": res("jailbreak", 0.4, detected=False),
               "pii": res("pii", 0.3, detected=True, entities=["PERSON"]), "toxicity": res("toxicity", 0.2, detected=False)}
    risk = score_risk(results, policy)
    expected = 0.40 * 0.5 + 0.25 * 0.4 + 0.20 * 0.3 + 0.15 * 0.2
    assert risk.weighted_score == pytest.approx(expected, abs=1e-4)
    assert risk.score == pytest.approx(expected, abs=1e-4)


def test_critical_finding_not_averaged_away(policy):
    results = {"prompt_injection": res("prompt_injection", 0.97), "jailbreak": res("jailbreak", 0.0),
               "pii": res("pii", 0.0, detected=False), "toxicity": res("toxicity", 0.0)}
    risk = score_risk(results, policy)
    assert risk.weighted_score < 0.5
    assert risk.score == pytest.approx(0.97)
    assert risk.critical_override


def test_critical_severity_floor(policy):
    results = {"secret_detection": res("secret_detection", 0.9, detected=True, severity=Severity.CRITICAL)}
    risk = score_risk(results, policy)
    assert risk.score >= policy.risk.critical_floor


def test_failed_detector_fails_closed(policy):
    results = {"prompt_injection": res("prompt_injection", 0.0, detected=False, status=DetectorStatus.ERROR)}
    risk = score_risk(results, policy)
    d = PolicyEngine().evaluate(results, risk, policy)
    assert d.decision == Decision.BLOCK
    assert risk.incomplete and "prompt_injection" in risk.failed_detectors


def test_pii_redacted_locally_and_forced_for_cloud(policy):
    policy = policy.model_copy(deep=True)
    policy.pii.action = Decision.ALLOW  # local deployments may allow PII...
    results = {"pii": res("pii", 0.5, detected=True, entities=["EMAIL_ADDRESS"])}
    risk = score_risk(results, policy)
    local = PolicyEngine().evaluate(results, risk, policy, provider=ProviderContext(name="ollama", is_local=True))
    cloud = PolicyEngine().evaluate(results, risk, policy, provider=ProviderContext(name="openai_compatible", is_local=False))
    assert local.decision == Decision.ALLOW and "pii" not in local.redact_categories
    assert cloud.decision == Decision.REDACT and "pii" in cloud.redact_categories  # ...but never to the cloud


def test_secret_always_blocks_for_cloud_even_if_policy_redacts(policy):
    policy = policy.model_copy(deep=True)
    policy.secret_detection.action = Decision.REDACT
    results = {"secret_detection": res("secret_detection", 0.95, detected=True, entities=["GITHUB_TOKEN"])}
    risk = score_risk(results, policy)
    local = PolicyEngine().evaluate(results, risk, policy, provider=ProviderContext(name="ollama", is_local=True))
    cloud = PolicyEngine().evaluate(results, risk, policy, provider=ProviderContext(name="x", is_local=False))
    assert "secret" in local.redact_categories
    assert cloud.decision == Decision.BLOCK


def test_uncertainty_band_triggers_verify_and_base_decision_is_allow(policy):
    results = {"prompt_injection": res("prompt_injection", 0.65, detected=False)}
    d = PolicyEngine().evaluate(results, score_risk(results, policy), policy)
    assert d.decision == Decision.VERIFY
    assert d.decision_without_verify() == Decision.ALLOW  # escalate-only: verifier can only add restrictions


def test_context_profile_bounds_thresholds(policy):
    # Detectors receive the profile-adjusted threshold, so `detected` differs per profile (0.8 vs 0.92).
    general_results = {"prompt_injection": res("prompt_injection", 0.85, detected=True)}
    research_results = {"prompt_injection": res("prompt_injection", 0.85, detected=False)}
    general = PolicyEngine().evaluate(general_results, score_risk(general_results, policy), policy)
    research = PolicyEngine().evaluate(research_results, score_risk(research_results, policy, "security_research"), policy,
                                       profile="security_research")
    assert general.decision == Decision.BLOCK
    assert research.decision == Decision.VERIFY  # 0.85 < 0.8*1.15, inside the verification band


def test_provider_not_permitted_blocks(policy):
    d = PolicyEngine().evaluate({}, score_risk({}, policy), policy, provider=ProviderContext(name="rogue", is_local=False))
    assert d.decision == Decision.BLOCK


@pytest.mark.parametrize("section,value,fragment", [
    ("secret_detection", {"action": "ALLOW"}, "BLOCK or REDACT"),
    ("prompt_injection", {"action": "VERIFY"}, "escalate-only"),
    ("prompt_injection", {"on_error": "ALLOW"}, "fail closed"),
    ("verification", {"escalate_only": False}, "escalate_only"),
    ("context_profiles", {"lax": {"threshold_multipliers": {"prompt_injection": 3.0}}}, "[0.8, 1.5]"),
    ("risk", {"verify_threshold": 0.9, "block_threshold": 0.5}, "verify_threshold"),
    ("pii", {"custom_entities": [{"name": "BAD", "patterns": [{"regex": "(unclosed"}]}]}, "invalid regex"),
    ("output", {"secret_action": "ALLOW"}, "secret_action"),
])
def test_policy_invariants_rejected(policy, section, value, fragment):
    store = PolicyStore(policy)
    with pytest.raises(PolicyValidationError) as exc:
        store.validate_candidate(section, value)
    assert any(fragment in e["msg"] or fragment in ".".join(e["loc"]) for e in exc.value.errors), exc.value.errors
