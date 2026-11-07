"""Secret detection, regex PII fallback and redaction/enforcement."""

from __future__ import annotations

import secrets
import string

import pytest

from sentinel.detection.base import DetectionContext
from sentinel.detection.normalizer import normalize
from sentinel.detection.pii_detector import PIIDetector
from sentinel.detection.secret_detector import SecretDetector, is_placeholder
from sentinel.engine.enforcement import Redactor, restore_placeholders


def rand(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def synthetic_secrets() -> dict[str, str]:
    return {
        "OPENAI_API_KEY": "sk-proj-" + rand(48),
        "GITHUB_TOKEN": "ghp_" + rand(36),
        "AWS_ACCESS_KEY_ID": "AKIA" + rand(16, string.ascii_uppercase + string.digits),
        "STRIPE_KEY": "sk_live_" + rand(24),
        "CONNECTION_STRING": f"postgresql://app:{rand(14)}@db.internal:5432/prod",
        "PRIVATE_KEY": "-----BEGIN RSA PRIVATE KEY-----\nMIIE" + rand(64) + "\n-----END RSA PRIVATE KEY-----",
    }


@pytest.mark.parametrize("kind", list(synthetic_secrets()))
async def test_secret_formats_detected(kind):
    value = synthetic_secrets()[kind]
    r = await SecretDetector().run(normalize(f"config: {value}", max_chars=10000), DetectionContext())
    assert r.detected, kind
    assert any(e.type == kind for e in r.entities), [e.type for e in r.entities]
    # Evidence never contains the full secret.
    assert all(value not in ev for ev in r.evidence)


@pytest.mark.parametrize("text", [
    "Set OPENAI_API_KEY=your_api_key_here in your .env",
    "export GITHUB_TOKEN=<YOUR_TOKEN>",
    "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
    "password = os.environ['DB_PASSWORD']",
    "api_key: ${API_KEY}",
    "My password is strong and I keep it safe.",
    "The token is valid for one hour.",
    "postgresql://user:password@localhost:5432/db",
    "commit 3f2a9c1e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39 fixed the bug",
    "request id 550e8400-e29b-41d4-a716-446655440000",
])
async def test_placeholders_and_ordinary_text_not_flagged(text):
    r = await SecretDetector().run(normalize(text, max_chars=10000), DetectionContext())
    assert not r.detected, (text, r.evidence)


def test_placeholder_heuristics():
    assert is_placeholder("sk-xxxxxxxxxxxxxxxxxxxx")
    assert is_placeholder("<API_KEY>")
    assert not is_placeholder("sk-proj-" + rand(40))


async def test_natural_language_password_detected():
    r = await SecretDetector().run(normalize("my password is Hunter2!x", max_chars=1000), DetectionContext())
    assert r.detected and r.entities[0].type == "PASSWORD"


async def test_regex_pii_fallback_detects_and_reports_degraded():
    det = PIIDetector()  # not loaded -> regex fallback
    r = await det.run(normalize("Email me at jane.roe@example.com or call +1 415 555 0132. Card 4111 1111 1111 1111.",
                                max_chars=1000), DetectionContext())
    types = {e.type for e in r.entities}
    assert {"EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD"} <= types
    assert r.status.value == "degraded" and r.method == "regex_fallback"


def test_checksum_validators():
    from sentinel.detection.pii_detector import iban_valid, verhoeff_valid

    assert verhoeff_valid("234123412346") and not verhoeff_valid("234123412345")
    assert iban_valid("GB82 WEST 1234 5698 7654 32") and not iban_valid("GB82 WEST 1234 5698 7654 33")


async def test_luhn_rejects_invalid_card():
    r = await PIIDetector().run(normalize("Order number 4111 1111 1111 1112", max_chars=1000), DetectionContext())
    assert "CREDIT_CARD" not in {e.type for e in r.entities}


async def test_redaction_placeholders_are_consistent_and_restorable():
    text = "Contact user@example.com. Again: user@example.com, or other@example.com."
    r = await PIIDetector().run(normalize(text, max_chars=1000), DetectionContext())
    red = Redactor()
    sanitized, infos = red.redact(text, r.spans)
    assert sanitized == "Contact [EMAIL_1]. Again: [EMAIL_1], or [EMAIL_2]."
    assert all(i.placeholder for i in infos)
    restored, n = restore_placeholders("Reply sent to [EMAIL_1]", red.mapping())
    assert restored == "Reply sent to user@example.com" and n == 1


def test_redactor_continues_numbering_from_session_mapping():
    red = Redactor({"pii:a@example.com": "[EMAIL_1]"})
    from sentinel.schemas.common import SensitiveSpan

    span = SensitiveSpan(type="EMAIL_ADDRESS", start=0, end=13, score=1.0, recognizer="t", value="b@example.com", category="pii")
    out, _ = red.redact("b@example.com", [span])
    assert out == "[EMAIL_2]"
