"""Enforcement layer: applies a PolicyDecision to text.

This is the only component that transforms user content (redaction) or
decides whether content is forwarded. Placeholder mappings live in memory for
the request and are only persisted (encrypted, TTL-bound) by the PII vault
when restoration is explicitly authorised by policy *and* requested.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, PrivateAttr

from sentinel.engine.policy_engine import PolicyDecision
from sentinel.schemas.common import Decision, DetectionResult, EntityInfo, SensitiveSpan

PLACEHOLDER_LABELS: dict[str, str] = {
    "EMAIL_ADDRESS": "EMAIL", "PHONE_NUMBER": "PHONE", "US_SSN": "SSN", "IP_ADDRESS": "IP", "CREDIT_CARD": "CREDIT_CARD",
    "PERSON": "PERSON", "IBAN_CODE": "IBAN", "US_PASSPORT": "PASSPORT", "IN_PASSPORT": "PASSPORT",
    "US_DRIVER_LICENSE": "DRIVER_LICENSE", "US_BANK_NUMBER": "BANK_ACCOUNT", "IN_AADHAAR": "AADHAAR", "IN_PAN": "PAN",
    "US_ITIN": "ITIN", "UK_NHS": "NHS_NUMBER", "IN_VOTER": "VOTER_ID", "MEDICAL_LICENSE": "MEDICAL_LICENSE",
    "CRYPTO": "CRYPTO_WALLET", "LOCATION": "LOCATION",
}

BLOCK_MESSAGE = "This request was blocked by the SentinelLLM security policy."
REVIEW_MESSAGE = "This request requires human review before it can be processed."


def placeholder_label(span: SensitiveSpan) -> str:
    if span.category == "secret":
        return "SECRET"
    return PLACEHOLDER_LABELS.get(span.type, span.type)


class Redactor:
    """Replaces spans with numbered placeholders, reusing placeholders for repeated values.

    ``existing`` (value -> placeholder) lets a session keep placeholders stable across turns.
    """

    def __init__(self, existing: dict[str, str] | None = None) -> None:
        self.value_to_ph: dict[str, str] = dict(existing or {})
        self.counters: dict[str, int] = {}
        for ph in self.value_to_ph.values():
            label, _, num = ph.strip("[]").rpartition("_")
            if num.isdigit():
                self.counters[label] = max(self.counters.get(label, 0), int(num))

    def _placeholder(self, span: SensitiveSpan) -> str:
        key = f"{span.category}:{span.value}"
        if key in self.value_to_ph:
            return self.value_to_ph[key]
        label = placeholder_label(span)
        self.counters[label] = self.counters.get(label, 0) + 1
        ph = f"[{label}_{self.counters[label]}]"
        self.value_to_ph[key] = ph
        return ph

    def redact(self, text: str, spans: list[SensitiveSpan]) -> tuple[str, list[EntityInfo]]:
        ordered = sorted(spans, key=lambda s: s.start)
        out: list[str] = []
        infos: list[EntityInfo] = []
        cursor = 0
        for s in ordered:
            if s.start < cursor:  # overlapping span already covered
                continue
            ph = self._placeholder(s)
            out.append(text[cursor:s.start])
            out.append(ph)
            infos.append(s.public(placeholder=ph))
            cursor = s.end
        out.append(text[cursor:])
        return "".join(out), infos

    def mapping(self) -> dict[str, str]:
        """placeholder -> original value (sensitive; in-memory only)."""
        return {ph: key.split(":", 1)[1] for key, ph in self.value_to_ph.items() if key.startswith("pii:")}


class EnforcementResult(BaseModel):
    decision: Decision
    forward: bool
    sanitized_text: str
    redactions: list[EntityInfo] = Field(default_factory=list)
    message: str | None = None

    _mapping: dict[str, str] = PrivateAttr(default_factory=dict)
    _redactor: Redactor | None = PrivateAttr(default=None)

    @property
    def placeholder_mapping(self) -> dict[str, str]:
        return self._mapping


def collect_spans(results: dict[str, DetectionResult], categories: set[str]) -> list[SensitiveSpan]:
    spans: list[SensitiveSpan] = []
    for name in ("secret_detection", "pii"):
        r = results.get(name)
        if r is not None:
            spans.extend(s for s in r.spans if s.category in categories)
    # Secrets win overlaps.
    spans.sort(key=lambda s: (s.category != "secret", s.start))
    kept: list[SensitiveSpan] = []
    for s in spans:
        if all(s.end <= k.start or s.start >= k.end for k in kept):
            kept.append(s)
    return sorted(kept, key=lambda s: s.start)


def enforce(
    text: str,
    results: dict[str, DetectionResult],
    decision: PolicyDecision,
    *,
    final_decision: Decision | None = None,
    redactor: Redactor | None = None,
) -> EnforcementResult:
    """Apply redactions for the categories the policy selected; decide forwarding."""
    final = final_decision or decision.decision
    redactor = redactor or Redactor()
    categories = set(decision.redact_categories)
    forward = final in (Decision.ALLOW, Decision.REDACT)
    if not forward:
        # Nothing is forwarded; still produce a fully-redacted preview for display/audit.
        categories = {"pii", "secret"}
    spans = collect_spans(results, categories)
    sanitized, infos = redactor.redact(text, spans) if spans else (text, [])
    message = None
    if final == Decision.BLOCK:
        message = BLOCK_MESSAGE
    elif final == Decision.HUMAN_REVIEW:
        message = REVIEW_MESSAGE
    res = EnforcementResult(
        decision=Decision.REDACT if (forward and infos and final == Decision.ALLOW) else final,
        forward=forward,
        sanitized_text=sanitized,
        redactions=infos,
        message=message,
    )
    res._mapping = redactor.mapping()
    res._redactor = redactor
    return res


def restore_placeholders(text: str, mapping: dict[str, str]) -> tuple[str, int]:
    """Replace placeholders with original values (only called when restoration is authorised)."""
    count = 0
    for ph, value in sorted(mapping.items(), key=lambda kv: -len(kv[0])):
        if ph in text:
            count += text.count(ph)
            text = text.replace(ph, value)
    return text, count
