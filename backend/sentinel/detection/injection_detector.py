"""Module B - Prompt injection detector (rules + local classifier).

Score combination (hybrid mode): ``score = max(rule_score, ml_probability)``.
``confidence`` is the classifier probability when the classifier ran, and
``None`` otherwise - rule weights are never presented as probabilities.
If the classifier is unavailable in hybrid mode the detector still runs its
rules and reports ``status=degraded`` so the policy engine can react.
"""

from __future__ import annotations

from sentinel.detection.base import DetectionContext, Detector, ml_text_for
from sentinel.detection.classifiers import ClassifierOutput, ModelRegistry
from sentinel.detection.normalizer import NormalizedInput
from sentinel.detection.rules import INJECTION_RULES, Rule, RuleMatchResult, RuleSet, noisy_or
from sentinel.schemas.common import DetectionResult, DetectorStatus, Severity, severity_from_score

_EXFIL_OR_OBFUSCATION = {"data_exfiltration"}


def corroborated(rule_res: RuleMatchResult | None) -> bool:
    """A classifier finding is corroborated when a non-dampened rule with meaningful weight also fired."""
    return bool(rule_res and any(h.weight >= 0.5 and not h.dampened for h in rule_res.hits))


def fuse(rule_score: float, ml_prob: float | None, rule_res: RuleMatchResult | None, ctx: DetectionContext) -> float:
    """Hybrid score fusion.

    * rules-only / ML-only modes return their own score unchanged (fair baselines);
    * hybrid: ``max(rule, ml)`` when rules corroborate the classifier, otherwise
      ``max(rule, ml * ml_weight)`` so an uncorroborated classifier spike lands in the
      verification band instead of blocking outright. ``ml_weight`` comes from policy.
    """
    if ml_prob is None:
        return rule_score
    if not ctx.use_rules:
        return ml_prob
    weight = float(ctx.options.get("ml_weight", 1.0))
    effective_ml = ml_prob if corroborated(rule_res) else ml_prob * weight
    return max(rule_score, effective_ml)


class PromptInjectionDetector(Detector):
    name = "prompt_injection"
    classifier_name = "prompt_injection"

    def __init__(self, registry: ModelRegistry, rules: list[Rule] | None = None) -> None:
        self.registry = registry
        self.ruleset = RuleSet(rules or INJECTION_RULES)

    async def _classify(self, inp: NormalizedInput) -> tuple[ClassifierOutput | None, ClassifierOutput | None]:
        clf = self.registry.get(self.classifier_name)
        if clf is None:
            return None, None
        main = await clf.predict(inp.text)
        decoded_text = ml_text_for(inp)
        decoded = await clf.predict(decoded_text) if decoded_text else None
        return main, decoded

    async def detect(self, inp: NormalizedInput, ctx: DetectionContext) -> DetectionResult:
        rule_res: RuleMatchResult | None = None
        rule_score = 0.0
        evidence: list[str] = []
        metadata: dict = {"mode": ctx.mode}

        if ctx.use_rules:
            rule_res = self.ruleset.match(inp.views, allow_dampening=ctx.options.get("edu_dampening", True))
            weights = [h.weight for h in rule_res.hits]
            # Hidden tag characters are themselves a strong smuggling indicator.
            if any(s.type == "hidden_unicode_tags" for s in inp.signals):
                weights.append(0.6)
                evidence.append("signal: invisible Unicode tag characters carry hidden text")
            rule_score = noisy_or(weights) if weights else 0.0
            evidence.extend(f"rule {h.rule_id}: {h.description}" + (" (decoded)" if h.view not in ("detection", "deleet", "cased") else "")
                            for h in rule_res.hits[:6])
            metadata["rule_score"] = round(rule_score, 4)
            metadata["rule_categories"] = rule_res.categories
            metadata["matches"] = [
                {"rule": h.rule_id, "category": h.category, "rule_weight": h.weight, "view": h.view, "snippet": h.snippet, "dampened": h.dampened}
                for h in rule_res.hits[:10]
            ]
            metadata["obfuscated"] = rule_res.obfuscated

        ml_prob: float | None = None
        status = DetectorStatus.OK
        if ctx.use_ml:
            main, decoded = await self._classify(inp)
            if main is None:
                metadata["ml_available"] = False
                status = DetectorStatus.DEGRADED if ctx.use_rules else DetectorStatus.UNAVAILABLE
            else:
                ml_prob = main.positive_prob
                metadata["ml"] = {"label": main.label, "probs": main.probs, "chunks": main.chunks, "truncated": main.truncated}
                if decoded is not None and decoded.positive_prob > ml_prob:
                    ml_prob = decoded.positive_prob
                    metadata["ml"]["decoded_prob"] = round(decoded.positive_prob, 6)
                metadata["ml_available"] = True
                if ml_prob >= 0.5:
                    evidence.append(f"classifier {self.registry.get(self.classifier_name).model_id} p(injection)={ml_prob:.3f}")  # type: ignore[union-attr]

        if status == DetectorStatus.UNAVAILABLE:
            return DetectionResult(
                detector=self.name, status=status, method="ml", reason="Injection classifier unavailable", metadata=metadata
            )

        score = fuse(rule_score, ml_prob, rule_res, ctx)
        if ml_prob is not None and ctx.use_rules:
            metadata["ml_corroborated"] = corroborated(rule_res)
        method = "hybrid" if (ctx.use_rules and ml_prob is not None) else ("ml" if ml_prob is not None else "rules")
        severity = severity_from_score(score)
        cats = set(rule_res.categories) if rule_res else set()
        if score >= 0.9 and ((rule_res and rule_res.obfuscated) or cats & _EXFIL_OR_OBFUSCATION):
            severity = Severity.CRITICAL

        if rule_res and rule_res.hits:
            reason = rule_res.hits[0].description
            if len(cats) > 1:
                reason += f" (+{len(cats) - 1} other categories)"
        elif ml_prob is not None and ml_prob >= ctx.threshold:
            reason = "Classifier identified instruction-injection patterns"
        else:
            reason = "No injection indicators" if score < ctx.threshold else "Weak injection indicators"

        return DetectionResult(
            detector=self.name,
            detected=score >= ctx.threshold,
            score=round(score, 4),
            confidence=round(ml_prob, 4) if ml_prob is not None else None,
            severity=severity if score >= 0.4 else Severity.NONE,
            reason=reason,
            evidence=evidence,
            method=method,
            status=status,
            metadata=metadata,
        )
