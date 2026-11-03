"""Input guard: heuristic detection of prompt injection and jailbreak framing.

This is a transparent, rule-based stand-in for a trained classifier (for
example a prompt-attack filter such as Amazon Bedrock Guardrails). It works in
two places:

* user turn (direct injection / jailbreak): a flagged prompt is refused before
  the model is called;
* tool output (indirect injection): flagged *sentences* are quarantined and
  the rest of the content is kept, so benign context survives. Remaining
  content is wrapped in spotlighting delimiters for live models.

The signals deliberately differ from the mock model's parser: the guard looks
for *properties of attacks* (addressing the AI, overriding instructions,
hidden encodings, egress to an address or URL, privilege terms), not for the
mock's exact templates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..text import decode_base64_spans, has_zero_width, normalize, sentences

SIGNALS: list[tuple[str, float, re.Pattern[str]]] = [
    ("override", 2.0, re.compile(r"\b(?:ignore|disregard|forget|override)\b.{0,30}\b(?:previous|prior|above|earlier|all|your)\b.{0,20}\b(?:instructions?|rules|guidelines|prompt)\b", re.I)),
    ("addresses_ai", 1.5, re.compile(r"\b(?:ai|llm|language model)\s+(?:assistants?|agents?|models?)\b|\bif you are an? (?:ai|assistant|llm)\b|\bnote to (?:the )?(?:ai|assistants?|agents?)\b|\b(?:assistant|agent)s? (?:must|should|are required)\b|^\s*(?:ai\s+)?(?:assistant|agent)\s*[:,]", re.I | re.M)),
    ("role_marker", 2.0, re.compile(r"(?:^|\n)\s*(?:system|assistant)\s*:|<\|im_start\|>|\[/?INST\]|###\s*instruction", re.I)),
    ("jailbreak_frame", 2.0, re.compile(r"\b(?:developer mode|do anything now|no restrictions|unrestricted ai|jailbreak|you are now|let'?s play a game|do not refuse|never refuse|do not apologi[sz]e)\b", re.I)),
    ("fiction_frame", 1.0, re.compile(r"\b(?:fictional|hypothetical(?:ly)?|in a story|pretend|role-?play|act as)\b", re.I)),
    ("prompt_extraction", 1.5, re.compile(r"\b(?:system prompt|initial instructions|hidden instructions|configuration id|config id)\b", re.I)),
    ("egress_to_address", 1.5, re.compile(r"\b(?:send|email|forward|cc|copy|post|upload|share)\b(?:[^.]|\.(?=\S)){0,80}\bto\s+[\w.+-]+@[\w.-]+", re.I)),
    ("url_template", 2.0, re.compile(r"https?://\S*\[[A-Z_]+\]|where \[[A-Z_]+\] is", re.I)),
    ("secret_path", 1.0, re.compile(r"/(?:secrets|hr|etc/shadow|\.ssh)\b|\b(?:token|password|credential|salar(?:y|ies))\b", re.I)),
    ("dangerous_shell", 2.0, re.compile(r"`[^`]*\b(?:curl|wget|nc|ncat|bash -c|sh\b|rm -rf|chmod|/etc/shadow)[^`]*`", re.I)),
    ("privilege", 1.5, re.compile(r"\b(?:grant|promote|elevate|assign)\b[^.]{0,40}\b(?:admin|administrator|superuser|owner)\b", re.I)),
    ("urgency", 0.5, re.compile(r"\b(?:important|urgent|immediately|right away|mandatory|required)\b", re.I)),
    ("render_link", 1.5, re.compile(r"!\[[^\]]*\]\(https?://", re.I)),
    ("decode_request", 1.5, re.compile(r"\bdecode\b.{0,30}\b(?:base64|this)\b", re.I)),
]
THRESHOLD = 2.0


@dataclass
class GuardVerdict:
    flagged: bool
    score: float
    signals: list[str] = field(default_factory=list)


def score_text(text: str) -> GuardVerdict:
    norm = normalize(text)
    hidden = decode_base64_spans(norm)
    probe = norm + ("\n" + "\n".join(hidden) if hidden else "")
    signals, score = [], 0.0
    for name, weight, pat in SIGNALS:
        if pat.search(probe):
            signals.append(name)
            score += weight
    if has_zero_width(text):
        signals.append("zero_width_chars")
        score += 1.0
    if hidden:
        signals.append("base64_payload")
        score += 1.0
    return GuardVerdict(score >= THRESHOLD, score, signals)


def check_user_prompt(text: str) -> GuardVerdict:
    return score_text(text)


@dataclass
class SanitizeResult:
    content: str
    quarantined: list[tuple[str, list[str]]]


def sanitize_tool_output(text: str) -> SanitizeResult:
    kept, removed = [], []
    for s in sentences(text):
        v = score_text(s)
        if v.flagged:
            removed.append((s, v.signals))
        else:
            kept.append(normalize(s))
    content = " ".join(kept)
    if removed:
        content += f" [input-guard: {len(removed)} suspected instruction(s) quarantined]"
    return SanitizeResult(content.strip(), removed)


def spotlight(source: str, text: str) -> str:
    """Datamark untrusted content for live models (the mock ignores this)."""
    return f"<<untrusted_data source={source}>>\n{text}\n<</untrusted_data>>"
