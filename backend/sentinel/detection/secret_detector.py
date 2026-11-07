"""Module E - Secret / credential detector.

Three layers:
1. Provider-specific token formats (AWS, GitHub, OpenAI, Anthropic, Slack,
   Stripe, Google, JWT, private keys, connection strings with credentials).
2. Credential assignments (``password=...``, ``api_key: ...``, "my password is ...").
3. High-entropy tokens near credential keywords.

Documentation placeholders (``your_api_key_here``, ``<TOKEN>``, ``sk-xxxx``,
``AKIAIOSFODNN7EXAMPLE``...) are recognised and ignored. Secret values are never
placed in evidence; previews show at most the first 4 characters.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from sentinel.detection.base import DetectionContext, Detector
from sentinel.detection.normalizer import NormalizedInput
from sentinel.schemas.common import DetectionResult, DetectorStatus, SensitiveSpan, Severity


@dataclass(frozen=True)
class SecretPattern:
    type: str
    pattern: re.Pattern[str]
    severity: Severity
    weight: float
    group: int = 0  # capture group holding the secret value


def _p(rx: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(rx, flags)


SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern("PRIVATE_KEY", _p(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]{0,8000}?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)"), Severity.CRITICAL, 1.0),
    SecretPattern("AWS_ACCESS_KEY_ID", _p(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"), Severity.CRITICAL, 0.97),
    SecretPattern("AWS_SECRET_ACCESS_KEY", _p(r"(?i)aws.{0,20}?(?:secret|private)?.{0,10}?(?:key|access).{0,10}?[\"'\s:=]+([A-Za-z0-9/+=]{40})\b"), Severity.CRITICAL, 0.95, 1),
    SecretPattern("GITHUB_TOKEN", _p(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b"), Severity.CRITICAL, 0.98),
    SecretPattern("ANTHROPIC_API_KEY", _p(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{40,}\b"), Severity.CRITICAL, 0.98),
    SecretPattern("OPENAI_API_KEY", _p(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b|\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}\b|\bsk-[A-Za-z0-9]{48}\b"), Severity.CRITICAL, 0.97),
    SecretPattern("SLACK_TOKEN", _p(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), Severity.CRITICAL, 0.95),
    SecretPattern("SLACK_WEBHOOK", _p(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}"), Severity.HIGH, 0.95),
    SecretPattern("STRIPE_KEY", _p(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b"), Severity.CRITICAL, 0.96),
    SecretPattern("GOOGLE_API_KEY", _p(r"\bAIza[0-9A-Za-z_-]{35}\b"), Severity.CRITICAL, 0.95),
    SecretPattern("HUGGINGFACE_TOKEN", _p(r"\bhf_[A-Za-z0-9]{30,}\b"), Severity.CRITICAL, 0.95),
    SecretPattern("JWT", _p(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), Severity.HIGH, 0.9),
    SecretPattern("CONNECTION_STRING", _p(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver|oracle)://[^\s:/@]+:([^\s@/]{3,})@[^\s/]+"), Severity.CRITICAL, 0.95, 1),
    SecretPattern("BEARER_TOKEN", _p(r"(?i)\bauthorization\s*:\s*bearer\s+([A-Za-z0-9._~+/=-]{20,})"), Severity.HIGH, 0.9, 1),
    SecretPattern("BASIC_AUTH_URL", _p(r"\bhttps?://[^\s:/@]+:([^\s@/]{3,})@[^\s/]+"), Severity.HIGH, 0.85, 1),
]

_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|pwd|pass|passphrase|secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?key|"
    r"access[_-]?token|auth[_-]?token|refresh[_-]?token|private[_-]?key|token|credentials?)\b[\"']?\s*(?:[:=]|=>)\s*[\"']?([^\s\"',;}{)(]{6,200})"
)
_NATURAL = re.compile(
    r"(?i)\b(?:my|the|our|admin|root|db|database|wifi|account)?\s*(password|passcode|pin|api key|secret key|access token|token)\s+(?:is|was|=|:)\s*[\"']?([^\s\"',;]{4,128})"
)
_CANDIDATE = re.compile(r"(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/=-]{20,200}(?![A-Za-z0-9_+/=-])")
_KEYWORD_NEAR = re.compile(r"(?i)\b(key|token|secret|password|passwd|credential|auth|bearer|api|private)\b")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

_PLACEHOLDER_WORDS = (
    "example", "sample", "dummy", "placeholder", "your", "xxxx", "changeme", "change_me", "change-me", "redacted",
    "insert", "fake", "replace", "secret_here", "key_here", "token_here", "_here", "-here", "todo", "<", ">", "{", "}",
    "${", "$(", "%(", "environ", "process.env", "getenv", "****", "....", "…", "my_", "my-",
)
_TRIVIAL = {"password", "123456", "12345678", "secret", "admin", "pass", "none", "null", "true", "false", "changeit",
            "qwerty", "letmein", "password123", "test", "testing", "default"}


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_placeholder(value: str) -> bool:
    v = value.strip().strip("\"'`")
    low = v.lower()
    if not v or low in _TRIVIAL:
        return True
    if any(w in low for w in _PLACEHOLDER_WORDS):
        return True
    most_common = Counter(low).most_common(1)[0][1]
    if most_common / len(low) >= 0.5:  # sk-xxxxxxxx, 000000000
        return True
    if low.startswith("sk-...") or low.endswith("..."):
        return True
    if re.fullmatch(r"(?i)(abc|123|abcd|1234|qwerty)+[a-z0-9]{0,4}", low):
        return True
    return False


def _credential_like(value: str, following: str = "") -> bool:
    """Filter out ordinary words and code expressions captured after 'password is' / 'token ='."""
    v = value.strip("\"'`")
    if following == "(" or following == "[" or following == ".":
        return False  # function call / attribute access: get_password(), cfg["pw"]
    if re.fullmatch(r"[a-z_][a-z0-9_]*", v) and not any(c.isdigit() for c in v):
        return len(v) >= 16 and "_" not in v  # long lowercase passphrase, not a snake_case identifier
    if re.fullmatch(r"[A-Za-z]+(\.[A-Za-z_]+)+", v):
        return False  # dotted attribute path: settings.db_password
    has_digit = any(c.isdigit() for c in v)
    has_symbol = any(not c.isalnum() for c in v)
    mixed = any(c.isupper() for c in v) and any(c.islower() for c in v)
    return has_digit or has_symbol or mixed or len(v) >= 12


def mask_secret(value: str) -> str:
    v = value.strip()
    return (v[:4] + "…" if len(v) > 8 else "…") + f"[{len(v)} chars]"


class SecretDetector(Detector):
    name = "secret_detection"

    def __init__(self, entropy_threshold: float = 4.0, hex_entropy_threshold: float = 3.0) -> None:
        self.entropy_threshold = entropy_threshold
        self.hex_entropy_threshold = hex_entropy_threshold

    def find_spans(self, text: str, *, include_entropy: bool = True) -> tuple[list[SensitiveSpan], int, dict[str, Severity]]:
        spans: list[SensitiveSpan] = []
        severities: dict[str, Severity] = {}
        ignored = 0
        taken: list[tuple[int, int]] = []

        def overlaps(s: int, e: int) -> bool:
            return any(not (e <= a or s >= b) for a, b in taken)

        def add(stype: str, s: int, e: int, weight: float, sev: Severity, rec: str) -> None:
            nonlocal ignored
            value = text[s:e]
            if is_placeholder(value):
                ignored += 1
                return
            if overlaps(s, e):
                return
            taken.append((s, e))
            spans.append(SensitiveSpan(type=stype, start=s, end=e, score=weight, recognizer=rec, value=value, category="secret"))
            prev = severities.get(stype, Severity.NONE)
            severities[stype] = sev if sev.value != prev.value and _rank(sev) > _rank(prev) else prev

        for sp in SECRET_PATTERNS:
            for m in sp.pattern.finditer(text):
                s, e = (m.start(sp.group), m.end(sp.group)) if sp.group else (m.start(), m.end())
                # Placeholder check uses the full match for context (e.g. "AKIA...EXAMPLE").
                if is_placeholder(m.group(0)) and sp.type != "PRIVATE_KEY":
                    ignored += 1
                    continue
                add(sp.type, s, e, sp.weight, sp.severity, f"pattern:{sp.type}")

        for rx, rec in ((_ASSIGNMENT, "assignment"), (_NATURAL, "natural_language")):
            for m in rx.finditer(text):
                value = m.group(2)
                s, e = m.start(2), m.end(2)
                if value.lower().startswith(("http://", "https://")) and "@" not in value:
                    continue
                following = text[e:e + 1]
                if not _credential_like(value, following):
                    continue
                stype = "PASSWORD" if "pass" in m.group(1).lower() or m.group(1).lower() == "pin" or "pwd" in m.group(1).lower() else "CREDENTIAL"
                add(stype, s, e, 0.85, Severity.HIGH, rec)

        if include_entropy:
            for m in _CANDIDATE.finditer(text):
                tok = m.group(0)
                if overlaps(m.start(), m.end()) or _UUID.match(tok):
                    continue
                if not (any(c.isdigit() for c in tok) and any(c.isalpha() for c in tok)):
                    continue
                is_hex = bool(re.fullmatch(r"[0-9a-fA-F]+", tok))
                ent = shannon_entropy(tok)
                threshold = self.hex_entropy_threshold if is_hex else self.entropy_threshold
                if ent < threshold or (is_hex and len(tok) < 32):
                    continue
                window = text[max(0, m.start() - 40): m.start()]
                if not _KEYWORD_NEAR.search(window):
                    continue  # high entropy alone (hashes, IDs) is not enough
                if not is_hex and not (any(c.isupper() for c in tok) and any(c.islower() for c in tok)):
                    continue
                add("HIGH_ENTROPY_SECRET", m.start(), m.end(), 0.7, Severity.MEDIUM, f"entropy:{ent:.2f}")

        spans.sort(key=lambda s: s.start)
        return spans, ignored, severities

    async def detect(self, inp: NormalizedInput, ctx: DetectionContext) -> DetectionResult:
        spans, ignored, severities = self.find_spans(inp.text, include_entropy=ctx.options.get("entropy", True))
        min_weight = float(ctx.options.get("min_weight", 0.6))
        spans = [s for s in spans if s.score >= min_weight]
        score = max((s.score for s in spans), default=0.0)
        severity = Severity.NONE
        for s in spans:
            sev = severities.get(s.type, Severity.HIGH)
            if _rank(sev) > _rank(severity):
                severity = sev
        counts: dict[str, int] = {}
        for s in spans:
            counts[s.type] = counts.get(s.type, 0) + 1
        result = DetectionResult(
            detector=self.name,
            detected=bool(spans),
            score=round(score, 4),
            confidence=None,  # deterministic pattern/entropy matches, not probabilities
            severity=severity,
            reason=("Credential material detected: " + ", ".join(sorted(counts))) if spans else "No secrets found",
            evidence=[f"{s.type} {mask_secret(s.value)} via {s.recognizer}" for s in spans[:8]],
            method="rules+entropy",
            status=DetectorStatus.OK,
            metadata={"secret_counts": counts, "ignored_placeholders": ignored, "rule_weight": score},
        )
        result.set_spans(spans)
        return result


def _rank(sev: Severity) -> int:
    from sentinel.schemas.common import SEVERITY_RANK

    return SEVERITY_RANK[sev]
