"""Text normalization helpers shared by the mock model and the defenses."""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata

ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"), None)
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_SENTENCE = re.compile(r"(?<=[.!?])\s+|\n+")


def has_zero_width(text: str) -> bool:
    return any(ord(c) in ZERO_WIDTH for c in text)


def normalize(text: str) -> str:
    """NFKC-fold and strip zero-width/soft-hyphen characters."""
    return unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH)


def decode_base64_spans(text: str) -> list[str]:
    """Return printable ASCII payloads hidden in base64 tokens."""
    out = []
    for tok in _B64_TOKEN.findall(text):
        padded = tok + "=" * (-len(tok) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            s = raw.decode("ascii")
        except UnicodeDecodeError:
            continue
        if s and all(32 <= ord(c) < 127 or c in "\n\t" for c in s) and " " in s:
            out.append(s)
    return out


def expand(text: str) -> str:
    """Normalized text plus any decoded base64 payloads appended."""
    norm = normalize(text)
    decoded = decode_base64_spans(norm)
    return norm if not decoded else norm + "\n" + "\n".join(decoded)


def sentences(text: str) -> list[str]:
    return [s for s in _SENTENCE.split(text) if s.strip()]
