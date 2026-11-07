"""Detector interface and shared helpers.

Detectors only *observe*: they return ``DetectionResult`` objects and never
block, redact or call providers. Decisions belong to the policy engine and
side effects to the enforcement layer.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal

from sentinel.detection.normalizer import NormalizedInput
from sentinel.schemas.common import DetectionResult, DetectorStatus, Severity, SEVERITY_RANK

logger = logging.getLogger(__name__)

DetectionMode = Literal["rules", "ml", "hybrid"]


@dataclass
class DetectionContext:
    """Per-call parameters supplied by the pipeline (sourced from policy configuration)."""

    stage: str = "input"  # input | output | context
    mode: DetectionMode = "hybrid"
    threshold: float = 0.5
    history: list[dict[str, str]] = field(default_factory=list)  # prior turns: {"role", "content"}
    options: dict[str, Any] = field(default_factory=dict)

    @property
    def use_rules(self) -> bool:
        return self.mode in ("rules", "hybrid")

    @property
    def use_ml(self) -> bool:
        return self.mode in ("ml", "hybrid")


class Detector(ABC):
    name: str

    @abstractmethod
    async def detect(self, inp: NormalizedInput, ctx: DetectionContext) -> DetectionResult:
        """Analyse ``inp`` and return a structured result."""

    async def run(self, inp: NormalizedInput, ctx: DetectionContext) -> DetectionResult:
        """Execute ``detect`` with timing and error capture. Errors are surfaced, never swallowed as 'safe'."""
        start = time.perf_counter()
        try:
            result = await self.detect(inp, ctx)
        except Exception as exc:
            logger.exception("Detector %s failed", self.name)
            result = DetectionResult(
                detector=self.name,
                status=DetectorStatus.ERROR,
                reason=f"Detector error: {type(exc).__name__}",
                metadata={"error_type": type(exc).__name__},
            )
        result.latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return result


def bump_severity(sev: Severity) -> Severity:
    order = [Severity.NONE, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    return order[min(len(order) - 1, SEVERITY_RANK[sev] + 1)]


def ml_text_for(inp: NormalizedInput, limit: int = 2000) -> str | None:
    """Concatenate decoded views (bounded) so classifiers also see de-obfuscated content."""
    decoded = [v.text for v in inp.decoded_views]
    if not decoded:
        return None
    joined = "\n".join(decoded)
    return joined[:limit]
