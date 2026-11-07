"""Module A - Input normalization.

Produces two kinds of text from an input:

* ``text`` - the canonical *forwarding* text. Only changes that are safe and
  meaning-preserving are applied: NFC normalization, CRLF -> LF, removal of
  control characters, bidi override/isolate characters (Trojan-Source style
  display attacks), invisible Unicode tag characters (ASCII smuggling) and
  zero-width spaces. ZWJ/ZWNJ are kept because they carry meaning in many
  scripts and emoji sequences.
* ``views`` - *detection-only* representations: NFKC + HTML-unescaped +
  homoglyph-folded + case-folded text, a de-leetspeak view, and bounded,
  validated decodings of suspicious encoded segments (base64, hex, URL
  encoding, unicode escapes, hidden tag characters, rot13 when mentioned).
  Views are analysed by detectors but never forwarded.

The original input is kept on the object for the request lifetime only; the
audit layer decides what (if anything) is persisted.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import html
import json
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote


class InputValidationError(ValueError):
    """Raised when an input violates size/structure limits."""

    def __init__(self, message: str, code: str = "invalid_input", status: int = 422):
        super().__init__(message)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class TextView:
    name: str  # detection | deleet | base64 | hex | url | unicode_escape | hidden_tags | rot13 | structured
    text: str
    decoded: bool = False  # True when produced by decoding an obfuscated segment


@dataclass(frozen=True)
class EncodingSignal:
    type: str
    count: int
    severity: str  # low | medium | high
    detail: str = ""


@dataclass
class NormalizedInput:
    original: str
    text: str
    views: list[TextView] = field(default_factory=list)
    signals: list[EncodingSignal] = field(default_factory=list)
    content_type: str = "text"
    removed_chars: int = 0

    @property
    def detection_text(self) -> str:
        return self.views[0].text if self.views else self.text

    @property
    def decoded_views(self) -> list[TextView]:
        return [v for v in self.views if v.decoded]

    def signal_summary(self) -> list[dict[str, Any]]:
        return [{"type": s.type, "count": s.count, "severity": s.severity, "detail": s.detail} for s in self.signals]


# ---------------------------------------------------------------------------
# Character classes
# ---------------------------------------------------------------------------
_BIDI = set("‪‫‬‭‮⁦⁧⁨⁩‎‏؜")
_ZERO_WIDTH_STRIP = set("​⁠﻿᠎")  # removed from forwarding text
_ZERO_WIDTH_KEEP = set("‌‍")  # ZWNJ/ZWJ: kept in forwarding text, removed in views
_SOFT_HYPHEN = "­"
_TAG_START, _TAG_END = 0xE0000, 0xE007F
_BLACK_FLAG = "\U0001F3F4"

_HOMOGLYPHS = str.maketrans(
    {
        # Cyrillic
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
        "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "ү": "y", "ɡ": "g", "к": "k",
        "м": "m", "н": "h", "т": "t", "в": "b",
        "А": "a", "В": "b", "Е": "e", "К": "k", "М": "m", "Н": "h", "О": "o", "Р": "p", "С": "c",
        "Т": "t", "Х": "x", "У": "y", "І": "i", "Ј": "j", "Ѕ": "s",
        # Greek
        "α": "a", "ο": "o", "ν": "v", "ι": "i", "ρ": "p", "κ": "k", "τ": "t", "υ": "u", "ε": "e",
        "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z", "Η": "h", "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n",
        "Ο": "o", "Ρ": "p", "Τ": "t", "Υ": "y", "Χ": "x",
    }
)
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/=_-])")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[\s:]?){16,}(?![0-9A-Fa-f])")
_HEX_ESC_RE = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){6,}")
_URL_ENC_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}[^%\s]{0,3}){6,}")
_UNI_ESC_RE = re.compile(r"(?:\\u[0-9A-Fa-f]{4}){4,}")
_NUM_ENTITY_RE = re.compile(r"&#(?:x[0-9A-Fa-f]{1,6}|\d{1,7});")
_ROT13_HINT = re.compile(r"\brot[\s-]?13\b", re.IGNORECASE)
_WS_RE = re.compile(r"[ \t\f\v]+")
_MULTI_NL = re.compile(r"\n{3,}")

_MAX_DECODE_CANDIDATES = 12
_MAX_SEGMENT_CHARS = 8000
_MAX_JSON_DEPTH = 20
_MAX_JSON_ITEMS = 5000


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for ch in s if ch.isprintable() or ch in "\n\t")
    return ok / len(s)


def _looks_like_text(s: str) -> bool:
    """Heuristic: decoded bytes should be human-readable language, not binary noise."""
    if len(s) < 6 or _printable_ratio(s) < 0.9:
        return False
    letters = sum(ch.isalpha() for ch in s)
    return letters / len(s) >= 0.5 and (" " in s or len(s) < 40)


def _try_b64(segment: str) -> str | None:
    seg = segment.strip()
    if len(seg) > _MAX_SEGMENT_CHARS:
        return None
    # Pure-alpha or pure-digit runs are words/numbers, not base64.
    if seg.isalpha() or seg.isdigit():
        return None
    padded = seg + "=" * (-len(seg) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(padded)
            text = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if _looks_like_text(text):
            return text
    return None


def _try_hex(segment: str) -> str | None:
    cleaned = re.sub(r"[\s:]", "", segment)
    if len(cleaned) % 2 or len(cleaned) > _MAX_SEGMENT_CHARS:
        return None
    try:
        text = bytes.fromhex(cleaned).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return text if _looks_like_text(text) else None


def _fold(text: str, casefold: bool = True) -> str:
    """Detection view: NFKC, HTML-unescape, strip invisibles, fold homoglyphs and case, collapse spaces."""
    t = html.unescape(text)
    t = unicodedata.normalize("NFKC", t)
    t = "".join(ch for ch in t if ch not in _ZERO_WIDTH_KEEP and ch != _SOFT_HYPHEN)
    if casefold:
        t = t.translate(_HOMOGLYPHS)
        t = t.casefold()
    t = _WS_RE.sub(" ", t)
    t = _MULTI_NL.sub("\n\n", t)
    return t.strip()


def _strip_combining(text: str) -> str:
    """Remove diacritics/zalgo combining marks for matching (detection-only)."""
    decomposed = unicodedata.normalize("NFD", text)
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))


def _extract_json_strings(obj: Any) -> list[str]:
    """Iteratively collect string keys/values from parsed JSON with depth/size bounds."""
    out: list[str] = []
    stack: list[tuple[Any, int]] = [(obj, 0)]
    items = 0
    while stack:
        cur, depth = stack.pop()
        items += 1
        if depth > _MAX_JSON_DEPTH:
            raise InputValidationError("Structured input exceeds maximum nesting depth", code="json_too_deep")
        if items > _MAX_JSON_ITEMS:
            raise InputValidationError("Structured input has too many elements", code="json_too_large")
        if isinstance(cur, str):
            out.append(cur)
        elif isinstance(cur, dict):
            for k, v in cur.items():
                if isinstance(k, str):
                    out.append(k)
                stack.append((v, depth + 1))
        elif isinstance(cur, list):
            stack.extend((v, depth + 1) for v in cur)
    return out


def normalize(text: str, *, max_chars: int, content_type: str = "text") -> NormalizedInput:
    """Validate and normalize input text. Raises ``InputValidationError`` on limit violations."""
    if not isinstance(text, str):
        raise InputValidationError("Input must be a string")
    if len(text) > max_chars:
        raise InputValidationError(
            f"Input exceeds maximum length of {max_chars} characters", code="input_too_large", status=413
        )

    signals: list[EncodingSignal] = []

    # --- hidden Unicode tag characters (ASCII smuggling) ---------------------
    hidden_chars: list[str] = []
    forward_chars: list[str] = []
    bidi = zw = ctrl = 0
    prev_is_flag = False
    for ch in text:
        cp = ord(ch)
        if _TAG_START <= cp <= _TAG_END:
            # Tag characters are legitimate only inside emoji flag tag sequences (U+1F3F4 ...).
            if prev_is_flag:
                forward_chars.append(ch)
                continue
            if 0xE0020 <= cp <= 0xE007E:
                hidden_chars.append(chr(cp - 0xE0000))
            continue
        prev_is_flag = ch == _BLACK_FLAG
        if ch in _BIDI:
            bidi += 1
            continue
        if ch in _ZERO_WIDTH_STRIP:
            zw += 1
            continue
        if ch in _ZERO_WIDTH_KEEP:
            zw += 1
        cat = unicodedata.category(ch)
        if cat == "Cc" and ch not in "\n\t\r":
            ctrl += 1
            continue
        forward_chars.append(ch)

    canonical = "".join(forward_chars).replace("\r\n", "\n").replace("\r", "\n")
    canonical = unicodedata.normalize("NFC", canonical)
    removed = len(text) - len(canonical)

    hidden_text = "".join(hidden_chars)
    if hidden_text:
        signals.append(EncodingSignal("hidden_unicode_tags", len(hidden_chars), "high", "Invisible tag characters encode text"))
    if bidi:
        signals.append(EncodingSignal("bidi_control", bidi, "medium", "Bidirectional override/isolate characters removed"))
    if zw >= 3:
        signals.append(EncodingSignal("zero_width", zw, "medium" if zw >= 10 else "low", "Zero-width characters present"))
    if ctrl:
        signals.append(EncodingSignal("control_chars", ctrl, "low", "Control characters removed"))

    # --- structured input ---------------------------------------------------
    structured_text: str | None = None
    if content_type == "json":
        try:
            parsed = json.loads(canonical)
        except json.JSONDecodeError as exc:
            raise InputValidationError("content_type is json but input is not valid JSON", code="invalid_json") from exc
        structured_text = "\n".join(_extract_json_strings(parsed))

    # --- detection views ----------------------------------------------------
    base_for_views = structured_text if structured_text is not None else canonical
    detection = _fold(_strip_combining(base_for_views))
    views: list[TextView] = [TextView("detection", detection)]
    # Case-preserving view for the few case-sensitive rules (e.g. the "DAN" acronym).
    views.append(TextView("cased", _fold(_strip_combining(base_for_views), casefold=False)))

    deleet = detection.translate(_LEET)
    if deleet != detection:
        views.append(TextView("deleet", deleet))

    if hidden_text:
        views.append(TextView("hidden_tags", _fold(hidden_text), decoded=True))

    # Numeric HTML entities used to spell out text.
    entities = _NUM_ENTITY_RE.findall(canonical)
    if len(entities) >= 3:
        signals.append(EncodingSignal("html_entity_obfuscation", len(entities), "medium", "Numeric HTML entities"))

    # Mixed-script words (homoglyph substitution).
    mixed = 0
    for word in re.findall(r"\w{3,}", canonical):
        has_latin = any("a" <= c.lower() <= "z" for c in word)
        has_other = any(c in "абвгдежзийклмнопрстуфхцчшщъыьэюяіјѕԁһӏαβγδεζηθικλμνξοπρστυφχψω" for c in word.lower())
        if has_latin and has_other:
            mixed += 1
    if mixed:
        signals.append(EncodingSignal("homoglyph_mixing", mixed, "medium", "Words mix Latin with Cyrillic/Greek letters"))

    # Bounded decoding of suspicious segments.
    decoded_count = 0
    for m in _B64_RE.finditer(base_for_views):
        if decoded_count >= _MAX_DECODE_CANDIDATES:
            break
        dec = _try_b64(m.group(0))
        if dec:
            decoded_count += 1
            views.append(TextView("base64", _fold(dec), decoded=True))
            # one extra layer for nested encodings
            for inner in _B64_RE.finditer(dec):
                inner_dec = _try_b64(inner.group(0))
                if inner_dec:
                    views.append(TextView("base64_nested", _fold(inner_dec), decoded=True))
                    break
    if decoded_count:
        signals.append(EncodingSignal("base64_text", decoded_count, "medium", "Base64 segments decode to readable text"))

    hex_count = 0
    for m in list(_HEX_RE.finditer(base_for_views))[:_MAX_DECODE_CANDIDATES]:
        dec = _try_hex(m.group(0))
        if dec:
            hex_count += 1
            views.append(TextView("hex", _fold(dec), decoded=True))
    for m in list(_HEX_ESC_RE.finditer(base_for_views))[:_MAX_DECODE_CANDIDATES]:
        dec = _try_hex(m.group(0).replace("\\x", ""))
        if dec:
            hex_count += 1
            views.append(TextView("hex", _fold(dec), decoded=True))
    if hex_count:
        signals.append(EncodingSignal("hex_text", hex_count, "medium", "Hex segments decode to readable text"))

    url_count = 0
    for m in list(_URL_ENC_RE.finditer(base_for_views))[:_MAX_DECODE_CANDIDATES]:
        dec = unquote(m.group(0))
        if dec != m.group(0) and _looks_like_text(dec):
            url_count += 1
            views.append(TextView("url", _fold(dec), decoded=True))
    if url_count:
        signals.append(EncodingSignal("url_encoding", url_count, "low", "URL-encoded text segments"))

    uni_count = 0
    for m in list(_UNI_ESC_RE.finditer(base_for_views))[:_MAX_DECODE_CANDIDATES]:
        try:
            dec = codecs.decode(m.group(0), "unicode_escape")
        except (UnicodeDecodeError, ValueError):
            continue
        if _looks_like_text(dec):
            uni_count += 1
            views.append(TextView("unicode_escape", _fold(dec), decoded=True))
    if uni_count:
        signals.append(EncodingSignal("unicode_escapes", uni_count, "medium", "Unicode escape sequences spell text"))

    if _ROT13_HINT.search(base_for_views):
        views.append(TextView("rot13", _fold(codecs.decode(base_for_views, "rot_13")), decoded=True))
        signals.append(EncodingSignal("rot13_hint", 1, "low", "Input references rot13"))

    return NormalizedInput(
        original=text,
        text=canonical,
        views=views,
        signals=signals,
        content_type=content_type,
        removed_chars=removed,
    )
