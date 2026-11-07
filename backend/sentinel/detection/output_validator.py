"""Module J - Output validator.

Inspects model-generated text before it reaches the caller:

* PII leakage (Presidio)            -> output.pii_action (default REDACT)
* credential leakage                -> output.secret_action (default BLOCK)
* toxicity                          -> output.toxicity_action
* system-prompt leakage (canary token + shingle overlap) -> BLOCK
* unsafe HTML / executable content / exfiltration links -> REDACT (stripped)
* invalid structured output (JSON / JSON Schema) -> BLOCK
* custom blocked patterns
* evidence support when evidence is supplied: *lexical overlap only*. This is
  reported as "evidence overlap" and is not factual verification.

Output decisions are restricted to ALLOW / REDACT / BLOCK.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, Field

from sentinel.detection.base import DetectionContext
from sentinel.detection.injection_detector import PromptInjectionDetector
from sentinel.detection.normalizer import normalize
from sentinel.detection.pii_detector import PIIDetector, options_from_policy
from sentinel.detection.secret_detector import SecretDetector
from sentinel.detection.toxicity_detector import ToxicityDetector
from sentinel.engine.enforcement import Redactor, collect_spans
from sentinel.engine.policy_schema import SentinelPolicy
from sentinel.schemas.common import Decision, DetectionResult, DetectorStatus, EntityInfo, most_restrictive

_UNSAFE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("script_tag", re.compile(r"<script\b[^>]*>[\s\S]*?(</script\s*>|$)", re.IGNORECASE)),
    ("iframe_object", re.compile(r"<(iframe|object|embed|applet|frame|frameset)\b[^>]*>([\s\S]*?</\1\s*>)?", re.IGNORECASE)),
    ("event_handler", re.compile(r"<[a-z][^>]*\son[a-z]+\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)[^>]*>", re.IGNORECASE)),
    ("javascript_url", re.compile(r"(?:href|src|action|formaction)\s*=\s*[\"']?\s*(?:javascript|vbscript|data:text/html)[^\"'\s>]*", re.IGNORECASE)),
    ("markdown_js_link", re.compile(r"\]\(\s*(?:javascript|vbscript|data:text/html):[^)]*\)", re.IGNORECASE)),
    ("meta_refresh", re.compile(r"<meta\b[^>]*http-equiv\s*=\s*[\"']?refresh[^>]*>", re.IGNORECASE)),
    ("exfil_image", re.compile(r"!\[[^\]]*\]\(\s*https?://[^)\s]*\?[^)\s]*=[^)\s]*\)", re.IGNORECASE)),
    ("form_tag", re.compile(r"<form\b[^>]*>", re.IGNORECASE)),
]
_UNSAFE_REPLACEMENT = "[removed unsafe content]"

_STOPWORDS = set("""a an the and or but if then else of to in on at by for with from as is are was were be been being this that these those
it its into about over under than so such not no can could would should will may might do does did have has had i you he she we they them
their our your his her which who whom what when where why how also more most other some any each all both very just there here""".split())
_WORD = re.compile(r"[a-z0-9]+")
_SENT = re.compile(r"(?<=[.!?])\s+")


class OutputCheck(BaseModel):
    check: str
    passed: bool
    action: Decision
    detail: str = ""


class GroundingReport(BaseModel):
    method: str = "lexical_evidence_overlap"
    sentences_evaluated: int
    supported: int
    support_ratio: float
    unsupported_examples: list[str] = Field(default_factory=list)
    note: str = "Lexical overlap with supplied evidence only; this is not factual verification."


class OutputValidation(BaseModel):
    decision: Decision
    checks: list[OutputCheck]
    results: dict[str, DetectionResult] = Field(default_factory=dict)
    sanitized_text: str
    redactions: list[EntityInfo] = Field(default_factory=list)
    grounding: GroundingReport | None = None

    @property
    def failed_checks(self) -> list[OutputCheck]:
        return [c for c in self.checks if not c.passed]


def _content_words(text: str) -> list[str]:
    return [w for w in _WORD.findall(text.lower()) if w not in _STOPWORDS and len(w) > 2]


def _shingles(words: list[str], n: int = 8) -> set[tuple[str, ...]]:
    return {tuple(words[i:i + n]) for i in range(max(0, len(words) - n + 1))}


def grounding_report(text: str, evidence: list[str]) -> GroundingReport:
    vocab: set[str] = set()
    for e in evidence:
        vocab.update(_content_words(e))
    evaluated = supported = 0
    unsupported: list[str] = []
    for sent in _SENT.split(text):
        words = _content_words(sent)
        if len(words) < 5:
            continue
        evaluated += 1
        overlap = sum(1 for w in words if w in vocab) / len(words)
        if overlap >= 0.5:
            supported += 1
        elif len(unsupported) < 3:
            unsupported.append(sent.strip()[:160])
    ratio = supported / evaluated if evaluated else 1.0
    return GroundingReport(sentences_evaluated=evaluated, supported=supported, support_ratio=round(ratio, 4),
                           unsupported_examples=unsupported)


class OutputValidator:
    def __init__(self, pii: PIIDetector, secret: SecretDetector, toxicity: ToxicityDetector,
                 injection: PromptInjectionDetector) -> None:
        self.pii = pii
        self.secret = secret
        self.toxicity = toxicity
        self.injection = injection

    async def validate(
        self,
        text: str,
        policy: SentinelPolicy,
        *,
        canary: str | None = None,
        system_prompt: str | None = None,
        response_format: str = "text",
        json_schema: dict[str, Any] | None = None,
        evidence: list[str] | None = None,
        max_chars: int = 200_000,
    ) -> OutputValidation:
        op = policy.output
        checks: list[OutputCheck] = []
        results: dict[str, DetectionResult] = {}
        if not op.enabled:
            return OutputValidation(decision=Decision.ALLOW, checks=[OutputCheck(check="output_validation", passed=True,
                                    action=Decision.ALLOW, detail="disabled by policy")], sanitized_text=text)

        norm = normalize(text[:max_chars], max_chars=max_chars)
        working = norm.text
        redact_categories: set[str] = set()

        # --- sensitive data ----------------------------------------------------
        pii_res = await self.pii.run(norm, DetectionContext(stage="output", options=_pii_options(policy)))
        results["pii"] = pii_res
        if pii_res.failed:
            checks.append(OutputCheck(check="pii_leakage", passed=False, action=Decision.BLOCK, detail="PII check failed (fail closed)"))
        elif pii_res.detected:
            checks.append(OutputCheck(check="pii_leakage", passed=False, action=op.pii_action, detail=pii_res.reason))
            if op.pii_action == Decision.REDACT:
                redact_categories.add("pii")
        else:
            checks.append(OutputCheck(check="pii_leakage", passed=True, action=Decision.ALLOW))

        sec_res = await self.secret.run(norm, DetectionContext(stage="output", options={"entropy": policy.secret_detection.entropy}))
        results["secret_detection"] = sec_res
        if sec_res.failed:
            checks.append(OutputCheck(check="credential_leakage", passed=False, action=Decision.BLOCK, detail="secret check failed (fail closed)"))
        elif sec_res.detected:
            checks.append(OutputCheck(check="credential_leakage", passed=False, action=op.secret_action, detail=sec_res.reason))
            if op.secret_action == Decision.REDACT:
                redact_categories.add("secret")
        else:
            checks.append(OutputCheck(check="credential_leakage", passed=True, action=Decision.ALLOW))

        # --- toxicity ----------------------------------------------------------
        if policy.toxicity.enabled:
            tox = await self.toxicity.run(norm, DetectionContext(stage="output", threshold=op.toxicity_threshold))
            results["toxicity"] = tox
            if tox.status == DetectorStatus.UNAVAILABLE:
                checks.append(OutputCheck(check="toxicity", passed=True, action=Decision.ALLOW, detail="classifier unavailable (not checked)"))
            elif tox.score >= op.toxicity_threshold:
                checks.append(OutputCheck(check="toxicity", passed=False, action=op.toxicity_action, detail=tox.reason))
            else:
                checks.append(OutputCheck(check="toxicity", passed=True, action=Decision.ALLOW))

        # --- system prompt leakage ---------------------------------------------
        leak_detail = ""
        if canary and canary in text:
            leak_detail = "response contains the per-request canary token"
        elif system_prompt:
            sp_words = _content_words(system_prompt)
            if len(sp_words) >= 20:
                sp = _shingles(sp_words)
                out = _shingles(_content_words(text))
                if sp and len(sp & out) / len(sp) >= 0.3:
                    leak_detail = f"response reproduces {len(sp & out) / len(sp):.0%} of system prompt 8-grams"
        checks.append(OutputCheck(check="system_prompt_leak", passed=not leak_detail,
                                  action=op.system_prompt_leak_action if leak_detail else Decision.ALLOW, detail=leak_detail))

        # --- unsafe HTML / executable content ----------------------------------
        unsafe_found = [name for name, rx in _UNSAFE_PATTERNS if rx.search(working)]
        if unsafe_found:
            checks.append(OutputCheck(check="unsafe_content", passed=False, action=op.unsafe_html_action,
                                      detail="found: " + ", ".join(unsafe_found)))
        else:
            checks.append(OutputCheck(check="unsafe_content", passed=True, action=Decision.ALLOW))

        # --- structured output -------------------------------------------------
        if response_format == "json":
            detail = ""
            try:
                parsed = json.loads(_strip_code_fence(text))
                if json_schema:
                    import jsonschema

                    jsonschema.Draft202012Validator(json_schema).validate(parsed)
            except json.JSONDecodeError as exc:
                detail = f"invalid JSON: {exc.msg}"
            except Exception as exc:  # jsonschema.ValidationError / SchemaError
                detail = f"schema violation: {str(getattr(exc, 'message', exc))[:200]}"
            checks.append(OutputCheck(check="structured_output", passed=not detail,
                                      action=op.invalid_structure_action if detail else Decision.ALLOW, detail=detail))

        # --- custom patterns ---------------------------------------------------
        for i, p in enumerate(op.blocked_patterns):
            if re.search(p.regex, working):
                checks.append(OutputCheck(check=f"blocked_pattern_{i}", passed=False, action=op.blocked_pattern_action,
                                          detail="matched configured pattern"))

        # --- injection echo (informational, for downstream agents) ------------
        inj = await self.injection.run(norm, DetectionContext(stage="output", mode="rules", threshold=op.injection_echo_threshold))
        results["prompt_injection"] = inj
        if inj.detected:
            checks.append(OutputCheck(check="injection_in_output", passed=False, action=Decision.ALLOW,
                                      detail=f"flagged only: {inj.reason}"))

        # --- grounding -----------------------------------------------------------
        grounding = None
        if evidence:
            grounding = grounding_report(text, evidence)
            low = op.grounding_min_support > 0 and grounding.support_ratio < op.grounding_min_support
            checks.append(OutputCheck(check="evidence_overlap", passed=not low,
                                      action=op.grounding_action if low else Decision.ALLOW,
                                      detail=f"support ratio {grounding.support_ratio:.2f} ({grounding.method})"))

        decision = most_restrictive(*(c.action for c in checks))
        sanitized = working
        redactions: list[EntityInfo] = []
        if decision != Decision.BLOCK:
            spans = collect_spans(results, redact_categories)
            if spans:
                sanitized, redactions = Redactor().redact(working, spans)
            if unsafe_found and op.unsafe_html_action == Decision.REDACT:
                for _, rx in _UNSAFE_PATTERNS:
                    sanitized = rx.sub(_UNSAFE_REPLACEMENT, sanitized)
        return OutputValidation(decision=decision, checks=checks, results=results, sanitized_text=sanitized,
                                redactions=redactions, grounding=grounding)


def _strip_code_fence(text: str) -> str:
    t = text.strip()
    m = re.fullmatch(r"```(?:json)?\s*([\s\S]*?)\s*```", t)
    return m.group(1) if m else t


def _pii_options(policy: SentinelPolicy) -> dict[str, Any]:
    return options_from_policy(policy.pii)
