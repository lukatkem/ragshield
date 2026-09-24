"""Stage 3 — the output filter: scan MODEL OUTPUT before the user sees it.

A defended pipeline is not enough — models can be talked into leaking on
the way out. Two families of runs get caught here: system-prompt leak
markers ("you are a helpful assistant that…") and secret-shaped strings
(API keys of the usual providers, AWS access keys, JWTs). Every hit is
replaced with ``[FILTERED:rule]`` and recorded.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


def _rx(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


# (rule, pattern) — applied together, non-overlapping, left to right
PATTERNS: tuple = (
    ("leak-marker", _rx(r"you\s+are\s+a\s+helpful\s+assistant\s+(?:that|who)\b")),
    ("leak-marker", _rx(r"your\s+instructions\s+are\b")),
    ("leak-marker", _rx(r"as\s+an\s+ai\s+language\s+model\b")),
    ("secret-api-key", re.compile(
        r"\b(?:sk-or-v1-|sk-ant-|sk-proj-|sk-)[A-Za-z0-9_-]{16,}")),
    ("secret-api-key", re.compile(r"\bnvapi-[A-Za-z0-9_-]{16,}")),
    ("secret-api-key", re.compile(r"\bgsk_[A-Za-z0-9]{16,}")),
    ("secret-aws-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("secret-jwt", re.compile(
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b")),
    ("secret-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
)


@dataclass(frozen=True)
class FilterHit:
    """One thing the output filter removed."""

    rule: str
    span: tuple
    snippet: str


@dataclass
class FilteredOutput:
    """Model output after filtering, plus the hits that made it so."""

    text: str
    hits: list = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.hits


def filter_output(text: str) -> FilteredOutput:
    """Scan model output and replace every leak/secret hit with
    ``[FILTERED:rule]``. Overlapping matches resolve to the longest."""
    found: list = []
    for rule, pattern in PATTERNS:
        for m in pattern.finditer(text):
            found.append(FilterHit(rule, m.span(), m.group(0)))

    found.sort(key=lambda h: (h.span[0], -(h.span[1] - h.span[0])))
    kept, taken = [], []
    for hit in found:
        start, end = hit.span
        if any(not (end <= s or start >= e) for s, e in taken):
            continue
        kept.append(hit)
        taken.append(hit.span)

    out, last = [], 0
    for hit in kept:
        start, end = hit.span
        out.append(text[last:start])
        out.append(f"[FILTERED:{hit.rule}]")
        last = end
    out.append(text[last:])
    return FilteredOutput("".join(out), kept)
