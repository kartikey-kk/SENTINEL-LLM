"""Module F - Toxicity detector.

Uses a configurable multi-label classifier (default ``unitary/toxic-bert``, the
model behind Detoxify's "original" checkpoint). Toxicity is reported as its
own category and is never folded into prompt-injection risk.

There is no rule-based fallback: if the model is unavailable the detector
reports ``unavailable`` and the policy's ``on_error`` setting decides what
happens (default for toxicity: allow, flagged).
"""

from __future__ import annotations

from sentinel.detection.base import DetectionContext, Detector
from sentinel.detection.classifiers import ModelRegistry
from sentinel.detection.normalizer import NormalizedInput
from sentinel.schemas.common import DetectionResult, DetectorStatus, Severity


class ToxicityDetector(Detector):
    name = "toxicity"
    classifier_name = "toxicity"

    def __init__(self, registry: ModelRegistry) -> None:
        self.registry = registry

    async def detect(self, inp: NormalizedInput, ctx: DetectionContext) -> DetectionResult:
        clf = self.registry.get(self.classifier_name)
        if clf is None:
            return DetectionResult(
                detector=self.name,
                status=DetectorStatus.UNAVAILABLE,
                method="ml",
                reason="Toxicity classifier unavailable",
                metadata={"ml_available": False},
            )
        out = await clf.predict(inp.text)
        prob = out.positive_prob
        labels = sorted([k for k, v in out.probs.items() if v >= 0.5], key=lambda k: -out.probs[k])
        if prob >= 0.9:
            severity = Severity.HIGH
        elif prob >= 0.7:
            severity = Severity.MEDIUM
        elif prob >= 0.5:
            severity = Severity.LOW
        else:
            severity = Severity.NONE
        return DetectionResult(
            detector=self.name,
            detected=prob >= ctx.threshold,
            score=round(prob, 4),
            confidence=round(prob, 4),
            severity=severity,
            reason=("Toxic content: " + ", ".join(labels)) if labels else "No toxicity above 0.5",
            evidence=[f"{k}={out.probs[k]:.3f}" for k in labels],
            method="ml",
            metadata={"probabilities": out.probs, "classification": labels or ["non_toxic"], "model": clf.model_id},
        )
