"""Module D - PII detector backed by Microsoft Presidio.

If Presidio or the spaCy model cannot be loaded, a deterministic regex engine
(email, phone, IP, Luhn-validated cards, SSN, Aadhaar, PAN, IBAN) is used and
the result is marked ``degraded`` - PII detection never silently turns off.

The detector returns spans (internal, with values) for the enforcement layer;
the public ``entities`` field carries only type/offset/score.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import threading
from typing import Any

from sentinel.detection.base import DetectionContext, Detector
from sentinel.detection.normalizer import NormalizedInput
from sentinel.schemas.common import DetectionResult, DetectorStatus, SensitiveSpan, Severity

logger = logging.getLogger(__name__)

# Relative sensitivity of each entity type (used for the "S" component of risk).
PII_SENSITIVITY: dict[str, float] = {
    "US_SSN": 0.95, "IN_AADHAAR": 0.95, "US_ITIN": 0.9, "CREDIT_CARD": 0.9, "US_PASSPORT": 0.9,
    "IN_PASSPORT": 0.9, "IBAN_CODE": 0.85, "IN_PAN": 0.85, "UK_NHS": 0.85, "US_BANK_NUMBER": 0.8,
    "US_DRIVER_LICENSE": 0.8, "IN_VOTER": 0.7, "MEDICAL_LICENSE": 0.7, "CRYPTO": 0.6,
    "EMAIL_ADDRESS": 0.5, "PHONE_NUMBER": 0.5, "IP_ADDRESS": 0.35, "PERSON": 0.3, "LOCATION": 0.2,
}

DEFAULT_ENTITIES = [
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "IP_ADDRESS", "CREDIT_CARD", "US_SSN", "US_PASSPORT",
    "US_DRIVER_LICENSE", "US_ITIN", "US_BANK_NUMBER", "IBAN_CODE", "UK_NHS", "IN_PAN", "IN_AADHAAR",
    "IN_PASSPORT", "IN_VOTER", "MEDICAL_LICENSE", "CRYPTO",
]


def options_from_policy(pii_policy: Any) -> dict[str, Any]:
    """Translate a ``PIIPolicy`` into detector options."""
    sensitivity = dict(PII_SENSITIVITY)
    for c in pii_policy.custom_entities:
        sensitivity[c.name] = c.sensitivity
    return {
        "entities": pii_policy.entities or None,
        "score_threshold": pii_policy.score_threshold,
        "entity_thresholds": pii_policy.entity_thresholds,
        "allow_list": pii_policy.allow_list,
        "custom_entities": [c.model_dump() for c in pii_policy.custom_entities],
        "sensitivity": sensitivity,
    }


def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_VERHOEFF_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
               [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
               [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
               [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_VERHOEFF_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
               [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
               [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]


def verhoeff_valid(number: str) -> bool:
    """Aadhaar numbers carry a Verhoeff check digit."""
    digits = [int(c) for c in number if c.isdigit()]
    c = 0
    for i, d in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][d]]
    return c == 0


def iban_valid(value: str) -> bool:
    s = value.replace(" ", "").upper()
    if not 15 <= len(s) <= 34:
        return False
    rearranged = s[4:] + s[:4]
    try:
        return int("".join(str(int(ch, 36)) for ch in rearranged)) % 97 == 1
    except ValueError:
        return False


# Checksum-validated types: high precision, so they also run alongside Presidio as a safety net.
CHECKSUM_VALIDATORS = {"CREDIT_CARD": luhn_valid, "IN_AADHAAR": verhoeff_valid, "IBAN_CODE": iban_valid}

_REGEX_RECOGNIZERS: list[tuple[str, re.Pattern[str], float]] = [
    ("EMAIL_ADDRESS", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), 0.9),
    ("CREDIT_CARD", re.compile(r"\b(?:\d[ -]?){12,18}\d\b"), 0.9),
    ("US_SSN", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), 0.85),
    ("IN_AADHAAR", re.compile(r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b"), 0.6),
    ("IN_PAN", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), 0.7),
    ("IBAN_CODE", re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}\s?[A-Z0-9]{1,4}\b"), 0.6),
    ("IP_ADDRESS", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), 0.6),
    ("PHONE_NUMBER", re.compile(r"(?<!\w)(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)|\d{2,4})[\s.-]?\d{3,4}[\s.-]?\d{3,4}(?!\w)"), 0.5),
]


class RegexPIIEngine:
    """Deterministic fallback when Presidio is unavailable."""

    def analyze(self, text: str, entities: list[str], recognizer: str = "regex_fallback") -> list[tuple[str, int, int, float, str]]:
        found: list[tuple[str, int, int, float, str]] = []
        wanted = set(entities)
        for etype, pattern, score in _REGEX_RECOGNIZERS:
            if etype not in wanted:
                continue
            for m in pattern.finditer(text):
                value = m.group(0)
                validator = CHECKSUM_VALIDATORS.get(etype)
                if validator is not None:
                    if not validator(value):
                        continue
                    score = 0.95  # checksum-validated
                if etype == "PHONE_NUMBER" and sum(c.isdigit() for c in value) < 9:
                    continue
                found.append((etype, m.start(), m.end(), score, recognizer))
        return found


def _resolve_overlaps(spans: list[SensitiveSpan]) -> list[SensitiveSpan]:
    """Keep non-overlapping spans, preferring secrets, then higher score, then longer spans."""
    ordered = sorted(spans, key=lambda s: (s.category != "secret", -s.score, -(s.end - s.start), s.start))
    kept: list[SensitiveSpan] = []
    for s in ordered:
        if all(s.end <= k.start or s.start >= k.end for k in kept):
            kept.append(s)
    return sorted(kept, key=lambda s: s.start)


class PIIDetector(Detector):
    name = "pii"

    def __init__(self, spacy_model: str = "en_core_web_md") -> None:
        self.spacy_model = spacy_model
        self._analyzer: Any = None
        self._regex = RegexPIIEngine()
        self._lock = threading.Lock()
        self._supported: set[str] = set()
        self._error: str | None = None
        self._custom_cache: dict[str, list[Any]] = {}

    @property
    def engine_name(self) -> str:
        return "presidio" if self._analyzer is not None else "regex_fallback"

    def load(self) -> None:
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider

            provider = NlpEngineProvider(
                nlp_configuration={"nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": self.spacy_model}]}
            )
            analyzer = AnalyzerEngine(nlp_engine=provider.create_engine(), supported_languages=["en"])
            # Presidio's default English registry does not load every predefined recognizer (e.g. Indian IDs);
            # register the ones SentinelLLM declares so they are not silently skipped.
            from presidio_analyzer import predefined_recognizers as pr

            present = set(analyzer.get_supported_entities(language="en"))
            for cls_name in ("InAadhaarRecognizer", "InPanRecognizer", "InPassportRecognizer", "InVoterRecognizer"):
                cls = getattr(pr, cls_name, None)
                if cls is None:
                    continue
                rec = cls()
                if not set(rec.supported_entities) <= present:
                    analyzer.registry.add_recognizer(rec)
            self._supported = set(analyzer.get_supported_entities(language="en"))
            self._analyzer = analyzer
            missing = sorted(set(DEFAULT_ENTITIES) - self._supported)
            if missing:
                logger.warning("PII entity types without a Presidio recognizer: %s", ", ".join(missing))
            logger.info("Presidio loaded with spaCy %s (%d entity types)", self.spacy_model, len(self._supported))
        except Exception as exc:
            self._analyzer = None
            self._error = f"{type(exc).__name__}: {str(exc)[:200]}"
            logger.warning("Presidio unavailable, using regex fallback: %s", self._error)

    def status(self) -> dict[str, Any]:
        return {
            "engine": self.engine_name,
            "spacy_model": self.spacy_model,
            "error": self._error,
            "supported_entities": sorted(self._supported),
            "unsupported_requested_entities": sorted(set(DEFAULT_ENTITIES) - self._supported) if self._analyzer else [],
            "checksum_validators": sorted(CHECKSUM_VALIDATORS),
        }

    def _custom_recognizers(self, custom: list[dict[str, Any]]) -> list[Any]:
        if not custom or self._analyzer is None:
            return []
        key = hashlib.sha256(json.dumps(custom, sort_keys=True).encode()).hexdigest()
        if key not in self._custom_cache:
            from presidio_analyzer import Pattern, PatternRecognizer

            recs = []
            for ent in custom:
                patterns = [Pattern(name=f"{ent['name']}_{i}", regex=p["regex"], score=float(p.get("score", 0.8)))
                            for i, p in enumerate(ent.get("patterns", []))]
                recs.append(PatternRecognizer(supported_entity=ent["name"], patterns=patterns, context=list(ent.get("context") or [])))
            self._custom_cache = {key: recs}
        return self._custom_cache[key]

    def _analyze_sync(self, text: str, entities: list[str], custom: list[dict[str, Any]]) -> list[tuple[str, int, int, float, str]]:
        custom_names = [c["name"] for c in custom]
        if self._analyzer is None:
            found = self._regex.analyze(text, entities)
            for ent in custom:
                for p in ent.get("patterns", []):
                    for m in re.finditer(p["regex"], text):
                        found.append((ent["name"], m.start(), m.end(), float(p.get("score", 0.8)), "custom_regex"))
            return found
        wanted = [e for e in entities if e in self._supported] + custom_names
        with self._lock:
            results = self._analyzer.analyze(
                text=text, language="en", entities=wanted, ad_hoc_recognizers=self._custom_recognizers(custom)
            )
        out = []
        for r in results:
            recognizer = (r.recognition_metadata or {}).get("recognizer_name", "presidio") if hasattr(r, "recognition_metadata") else "presidio"
            out.append((r.entity_type, r.start, r.end, float(r.score), str(recognizer)))
        # Safety net: checksum-validated patterns (Luhn / Verhoeff / mod-97) catch formats Presidio's
        # recognizers miss; overlaps with Presidio findings are resolved later.
        checksum_types = [e for e in entities if e in CHECKSUM_VALIDATORS]
        out.extend(self._regex.analyze(text, checksum_types, recognizer="checksum_validator"))
        return out

    async def find_spans(self, text: str, options: dict[str, Any]) -> list[SensitiveSpan]:
        entities = options.get("entities") or DEFAULT_ENTITIES
        custom = options.get("custom_entities") or []
        threshold = float(options.get("score_threshold", 0.4))
        per_entity = options.get("entity_thresholds") or {}
        allow = {a.lower() for a in (options.get("allow_list") or [])}
        raw = await asyncio.to_thread(self._analyze_sync, text, list(entities), list(custom))
        spans = []
        for etype, start, end, score, recognizer in raw:
            value = text[start:end]
            if score < float(per_entity.get(etype, threshold)) or value.lower() in allow or not value.strip():
                continue
            spans.append(SensitiveSpan(type=etype, start=start, end=end, score=score, recognizer=recognizer, value=value, category="pii"))
        return _resolve_overlaps(spans)

    async def detect(self, inp: NormalizedInput, ctx: DetectionContext) -> DetectionResult:
        spans = await self.find_spans(inp.text, ctx.options)
        sensitivity = ctx.options.get("sensitivity") or PII_SENSITIVITY
        risk = max((float(sensitivity.get(s.type, 0.5)) * s.score for s in spans), default=0.0)
        top = max((float(sensitivity.get(s.type, 0.5)) for s in spans), default=0.0)
        severity = Severity.NONE
        if spans:
            severity = Severity.HIGH if top >= 0.85 else Severity.MEDIUM if top >= 0.5 else Severity.LOW
        counts: dict[str, int] = {}
        for s in spans:
            counts[s.type] = counts.get(s.type, 0) + 1
        result = DetectionResult(
            detector=self.name,
            detected=bool(spans),
            score=round(min(1.0, risk), 4),
            confidence=None,  # Presidio scores are recognizer confidences per entity, reported per entity
            severity=severity,
            reason=("Sensitive personal data: " + ", ".join(f"{k}x{v}" for k, v in sorted(counts.items()))) if spans else "No PII found",
            evidence=[f"{t} detected ({n})" for t, n in sorted(counts.items())],
            method=self.engine_name,
            status=DetectorStatus.OK if self._analyzer is not None else DetectorStatus.DEGRADED,
            metadata={"entity_counts": counts, "engine": self.engine_name},
        )
        result.set_spans(spans)
        return result
