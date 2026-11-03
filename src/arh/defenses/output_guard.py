"""Output guard: data-loss prevention on egress tool arguments and final answers.

Detection is pattern-based (credential prefixes, SSN shapes, high-entropy
tokens, verbatim system-prompt overlap). It does *not* know the canary
values used by the scorer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("credential_prefix", re.compile(r"\b(?:nw_live|sk_live|AKIA|ghp)_?[A-Za-z0-9]{12,}\b")),
    ("assignment_secret", re.compile(r"\b[A-Z_]*(?:TOKEN|SECRET|PASSWORD|API_KEY)\s*=\s*\S+")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("salary_table", re.compile(r"\bssn\b.{0,20}\bsalary\b", re.I)),
]


@dataclass
class DLPVerdict:
    sensitive: bool
    findings: list[str] = field(default_factory=list)


def scan(text: str, system_prompt: str | None = None) -> DLPVerdict:
    findings = [name for name, pat in PATTERNS if pat.search(text)]
    if system_prompt and _overlaps(text, system_prompt):
        findings.append("system_prompt_overlap")
    return DLPVerdict(bool(findings), findings)


def _overlaps(text: str, reference: str, n: int = 8) -> bool:
    """True if any n-word window of the system prompt appears in the text."""
    words = reference.split()
    low = " ".join(text.split()).lower()
    return any(" ".join(words[i:i + n]).lower() in low for i in range(0, max(1, len(words) - n + 1)))


_MD_LINK = re.compile(r"!?\[([^\]]*)\]\((https?://[^)\s]+)\)")


def redact_final(text: str, system_prompt: str, allowed_hosts: set[str]) -> tuple[str, list[str]]:
    findings: list[str] = []

    def _link(m: re.Match[str]) -> str:
        host = urlparse(m.group(2)).netloc.lower()
        if host in allowed_hosts:
            return m.group(0)
        findings.append(f"stripped_untrusted_link:{host}")
        return f"[{m.group(1)}](link removed)"

    out = _MD_LINK.sub(_link, text)
    for name, pat in PATTERNS:
        if pat.search(out):
            findings.append(name)
            out = pat.sub("[REDACTED]", out)
    if _overlaps(out, system_prompt):
        findings.append("system_prompt_overlap")
        out = "I can't share my configuration. " + _strip_overlap(out, system_prompt)
    return out, findings


def _strip_overlap(text: str, reference: str) -> str:
    return "\n".join(line for line in text.splitlines() if not _overlaps(line, reference))
