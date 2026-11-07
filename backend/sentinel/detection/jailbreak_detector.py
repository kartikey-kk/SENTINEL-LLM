"""Module C - Jailbreak detector.

Combines deterministic jailbreak rules, a configurable classifier and
multi-turn indicators computed over the conversation history. Ordinary
role-play ("pretend you are a pirate") is not penalised: persona rules only
fire when paired with restriction-removal or unfiltered-persona language.
"""

from __future__ import annotations

import re

from sentinel.detection.base import DetectionContext, Detector, ml_text_for
from sentinel.detection.classifiers import ModelRegistry
from sentinel.detection.injection_detector import corroborated, fuse
from sentinel.detection.normalizer import NormalizedInput, normalize
from sentinel.detection.rules import JAILBREAK_RULES, Rule, RuleSet, noisy_or
from sentinel.schemas.common import DetectionResult, DetectorStatus, Severity, severity_from_score

_REFERENCE = re.compile(
    r"\b(as (we|you) (agreed|discussed|established|said)|remember (that )?(you are|you're|your (role|persona|character|rules))|"
    r"you (already )?(promised|agreed)|continue (as|being|in character|the (game|roleplay))|stay in character|"
    r"like (before|last time|earlier)|you said (you would|you could|you can))\b",
    re.IGNORECASE,
)
_REFUSAL = re.compile(r"\b(i can'?t|i cannot|i'?m sorry,? but|i am unable|i won'?t|i'?m not able|i must decline|i can not)\b", re.IGNORECASE)
_REFRAME = re.compile(
    r"\b(hypothetical(ly)?|just pretend|for a (story|novel|game|movie|screenplay)|in fiction|it'?s (just )?fiction|"
    r"purely academic|for educational purposes|asking for a friend|in a fictional)\b",
    re.IGNORECASE,
)

MAX_HISTORY_TURNS = 10
MAX_TURN_CHARS = 4000


class JailbreakDetector(Detector):
    name = "jailbreak"
    classifier_name = "jailbreak"

    def __init__(self, registry: ModelRegistry, rules: list[Rule] | None = None) -> None:
        self.registry = registry
        self.ruleset = RuleSet(rules or JAILBREAK_RULES)

    def _multi_turn(self, inp: NormalizedInput, history: list[dict[str, str]]) -> tuple[float, list[str]]:
        if not history:
            return 0.0, []
        turns = history[-MAX_HISTORY_TURNS:]
        user_scores: list[float] = []
        last_assistant_refused = False
        for turn in turns:
            content = (turn.get("content") or "")[:MAX_TURN_CHARS]
            if turn.get("role") == "user":
                try:
                    n = normalize(content, max_chars=MAX_TURN_CHARS)
                except ValueError:
                    continue
                user_scores.append(self.ruleset.match(n.views).score)
            elif turn.get("role") == "assistant":
                last_assistant_refused = bool(_REFUSAL.search(content))

        indicators: list[tuple[float, str]] = []
        current = inp.detection_text
        prior_max = max(user_scores, default=0.0)
        if prior_max >= 0.35 and _REFERENCE.search(current):
            indicators.append((0.7, "references a persona/agreement established in earlier turns"))
        if last_assistant_refused and _REFRAME.search(current):
            indicators.append((0.6, "reframes a request the model previously refused"))
        recent = user_scores[-3:]
        if len(recent) == 3 and recent[0] < recent[1] < recent[2] and recent[2] >= 0.5:
            indicators.append((0.5, "escalating jailbreak indicators across turns"))
        if prior_max >= 0.7:
            indicators.append((round(prior_max * 0.5, 3), "earlier turn contained a jailbreak attempt"))
        score = noisy_or([w for w, _ in indicators]) if indicators else 0.0
        return score, [d for _, d in indicators]

    async def detect(self, inp: NormalizedInput, ctx: DetectionContext) -> DetectionResult:
        evidence: list[str] = []
        metadata: dict = {"mode": ctx.mode}
        rule_score = 0.0
        multi_score = 0.0
        rule_res = None
        if ctx.use_rules:
            rule_res = self.ruleset.match(inp.views, allow_dampening=ctx.options.get("edu_dampening", True))
            rule_score = rule_res.score
            evidence.extend(f"rule {h.rule_id}: {h.description}" for h in rule_res.hits[:6])
            metadata["rule_score"] = rule_score
            metadata["rule_categories"] = rule_res.categories
            metadata["matches"] = [
                {"rule": h.rule_id, "category": h.category, "rule_weight": h.weight, "view": h.view, "snippet": h.snippet, "dampened": h.dampened}
                for h in rule_res.hits[:10]
            ]
            multi_score, multi_reasons = self._multi_turn(inp, ctx.history)
            if multi_reasons:
                metadata["multi_turn_score"] = multi_score
                metadata["multi_turn_indicators"] = multi_reasons
                evidence.extend(f"multi-turn: {r}" for r in multi_reasons)

        ml_prob: float | None = None
        status = DetectorStatus.OK
        if ctx.use_ml:
            clf = self.registry.get(self.classifier_name)
            if clf is None:
                metadata["ml_available"] = False
                status = DetectorStatus.DEGRADED if ctx.use_rules else DetectorStatus.UNAVAILABLE
            else:
                out = await clf.predict(inp.text)
                ml_prob = out.positive_prob
                decoded_text = ml_text_for(inp)
                if decoded_text:
                    dec = await clf.predict(decoded_text)
                    ml_prob = max(ml_prob, dec.positive_prob)
                metadata["ml"] = {"label": out.label, "probs": out.probs, "chunks": out.chunks}
                metadata["ml_available"] = True
                if ml_prob >= 0.5:
                    evidence.append(f"classifier {clf.model_id} p(jailbreak)={ml_prob:.3f}")

        if status == DetectorStatus.UNAVAILABLE:
            return DetectionResult(detector=self.name, status=status, method="ml", reason="Jailbreak classifier unavailable", metadata=metadata)

        single = fuse(rule_score, ml_prob, rule_res, ctx)
        if ml_prob is not None and ctx.use_rules:
            metadata["ml_corroborated"] = corroborated(rule_res)
        score = noisy_or([single, multi_score]) if multi_score else single
        method = "hybrid" if (ctx.use_rules and ml_prob is not None) else ("ml" if ml_prob is not None else "rules")
        severity = severity_from_score(score)
        if score >= 0.95 and rule_res and len(rule_res.categories) >= 2:
            severity = Severity.CRITICAL

        if rule_res and rule_res.hits:
            reason = rule_res.hits[0].description
        elif multi_score >= ctx.threshold:
            reason = "Multi-turn manipulation pattern"
        elif ml_prob is not None and ml_prob >= ctx.threshold:
            reason = "Classifier identified jailbreak patterns"
        else:
            reason = "No jailbreak indicators" if score < ctx.threshold else "Weak jailbreak indicators"

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
