"""Stage 1 — prompt-injection detection for untrusted RAG documents.

Retrieved chunks are attacker-controlled text wearing a trustworthy
pipeline badge. Six heuristic families — each weighted and named — hunt
the classic moves: instruction overrides, role escapes, data-exfiltration
requests, hidden encoded payloads, unicode confusables, delimiter breaking.

Scoring: each rule contributes its weight for the first hit, half weight
for each further hit (diminishing returns for repetition), capped at 1.0.

    score >= 0.70   blocked
    score >= 0.35   suspicious
    otherwise       clean
"""
from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field

BLOCKED_AT = 0.70
SUSPICIOUS_AT = 0.35

# Cyrillic / Greek letters that pass for Latin. Purely foreign text (all
# Cyrillic) is just another language — only *mixing* lookalikes into Latin
# words is the attack, so detection and folding both key off this table.
CONFUSABLE_FOLD: dict[str, str] = {
    # cyrillic small
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ј": "j", "һ": "h", "ң": "n",
    # cyrillic capital
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "У": "Y",
    # greek small
    "ο": "o", "α": "a", "ν": "v", "κ": "k", "τ": "t", "ρ": "p", "ι": "i",
    # greek capital
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}
_CONFUSABLES = frozenset(CONFUSABLE_FOLD)

_WORD = re.compile(r"[^\W\d_]+", re.UNICODE)
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}|[A-Za-z0-9_-]{40,}={0,2}")
_FENCE_RUN = re.compile(r"`{3,}|[-=*_#]{3,}")
_B64_PRINTABLE_RATIO = 0.80


def _rx(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


@dataclass(frozen=True)
class Rule:
    """One named heuristic: a family, a weight, and its trigger patterns."""

    id: str
    family: str
    weight: float
    description: str
    patterns: tuple


PHRASE_RULES: tuple[Rule, ...] = (
    Rule(
        "instruction-override", "instruction-override", 0.50,
        "explicit attempts to cancel or replace prior instructions",
        (
            _rx(r"ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier|initial)\s+instructions"),
            _rx(r"ignore\s+(?:your|these|its)\s+(?:instructions|rules)"),
            _rx(r"disregard\s+(?:all|any|your|the)\s+(?:previous|prior|above|earlier|instructions|rules)"),
            _rx(r"disregard\s+all\b"),
            _rx(r"forget\s+(?:all\s+|your\s+|any\s+)?(?:rules|instructions|training)\b"),
            _rx(r"override\s+(?:your|all|any|the)\s+(?:instructions|rules|constraints)"),
        ),
    ),
    Rule(
        "instruction-hijack", "instruction-override", 0.45,
        "attempts to install a new persona or a fresh instruction stream",
        (
            _rx(r"\byou\s+are\s+now\b"),
            _rx(r"from\s+now\s+on[,:]?\s+you\b"),
            _rx(r"\bnew\s+instructions\s*:"),
            _rx(r"\bsystem\s+prompt\s*:"),
            _rx(r"\bupdated\s+(?:system\s+)?instructions\s*:"),
        ),
    ),
    Rule(
        "role-pretend", "role-escape", 0.45,
        "asks the model to adopt a new identity wholesale",
        (
            _rx(r"pretend\s+(?:you\s+are|to\s+be)"),
            _rx(r"play\s+the\s+role\s+of"),
            _rx(r"roleplay\s+as\b"),
        ),
    ),
    Rule(
        "role-act-as", "role-escape", 0.30,
        "generic role-play requests — weak on its own (\"act as a team\" is fine)",
        (_rx(r"\bact\s+as\b"),),
    ),
    Rule(
        "developer-mode", "role-escape", 0.45,
        "classic jailbreak personas: DAN, developer mode, do-anything-now",
        (
            _rx(r"developer\s+mode"),
            _rx(r"do\s+anything\s+now"),
            _rx(r"\bDAN\b"),
        ),
    ),
    Rule(
        "data-exfiltration", "data-exfiltration", 0.50,
        "asks the model to print its system prompt or standing instructions",
        (
            _rx(r"repeat\s+(?:your|the)\s+(?:system\s+prompt|instructions)"),
            _rx(r"print\s+(?:your|the)\s+(?:system\s+prompt|instructions)"),
            _rx(r"(?:reveal|show|display|output)\s+(?:your|the)\s+(?:system\s+prompt|initial\s+instructions|instructions)"),
            _rx(r"tell\s+me\s+your\s+(?:system\s+prompt|instructions|rules)"),
            _rx(r"what\s+(?:are|is)\s+your\s+(?:rules|instructions|system\s+prompt)\b"),
            _rx(r"your\s+(?:rules|instructions)\s+above\b"),
        ),
    ),
    Rule(
        "encoding-request", "encoding", 0.35,
        "asks the reader to decode a hidden payload (rot13, atbash, decode-the-following)",
        (
            _rx(r"\brot[-\s]?13\b"),
            _rx(r"\batbash\b"),
            _rx(r"\bdecode\s+(?:the|this|it|following|above)\b"),
        ),
    ),
)

WEIGHT_CONFUSABLES = 0.45
WEIGHT_INVISIBLE = 0.20
WEIGHT_DELIMITER = 0.20


@dataclass(frozen=True)
class Match:
    """One heuristic hit: which rule fired, where, and how much it weighs."""

    rule: str
    family: str
    span: tuple
    weight: float
    snippet: str
    detail: str = ""


@dataclass
class Detection:
    """The detector's verdict on one document."""

    score: float
    matches: list = field(default_factory=list)
    verdict: str = ""

    def __post_init__(self) -> None:
        if not self.verdict:
            self.verdict = verdict_for(self.score)


def verdict_for(score: float) -> str:
    """Map a 0..1 score to a verdict: clean / suspicious / blocked."""
    if score >= BLOCKED_AT:
        return "blocked"
    if score >= SUSPICIOUS_AT:
        return "suspicious"
    return "clean"


def fold_to_ascii(text: str) -> str:
    """Fold confusable Cyrillic/Greek letters to their Latin twins.

    The map is strictly one character to one character, so string spans in
    the folded text line up with the original."""
    return "".join(CONFUSABLE_FOLD.get(ch, ch) for ch in text)


def _is_confusable(ch: str) -> bool:
    if ch not in _CONFUSABLES:
        return False
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return False
    return "CYRILLIC" in name or "GREEK" in name


def _find_confusables(text: str) -> list:
    """Cyrillic/Greek lookalikes smuggled inside otherwise-Latin words.

    A document written entirely in Russian is a language, not an attack;
    only mixed-script words like \"іgnore\" (Cyrillic і) count."""
    hits = []
    for m in _WORD.finditer(text):
        word = m.group(0)
        mixed = any(_is_confusable(ch) for ch in word) and any(ch.isascii() for ch in word)
        if mixed:
            hits.append(Match("unicode-confusables", "unicode-tricks", m.span(),
                              WEIGHT_CONFUSABLES, word,
                              "cyrillic/greek lookalikes inside a latin word"))
    return hits


def _find_invisible(text: str) -> list:
    """Zero-width and bidi control characters (unicode category Cf)."""
    positions = [i for i, ch in enumerate(text) if unicodedata.category(ch) == "Cf"]
    if not positions:
        return []
    first = positions[0]
    return [Match("unicode-invisible", "unicode-tricks", (first, first + 1),
                  WEIGHT_INVISIBLE, repr(text[first]),
                  f"{len(positions)} zero-width/bidi control character(s) present")]


def _decodes_to_text(blob: str) -> bool:
    """True if the blob is valid base64 (standard or urlsafe) whose decoded
    bytes are mostly printable — i.e. a hidden message, not a hash or a long
    identifier."""
    stripped = blob.rstrip("=")
    if not stripped or len(stripped) % 4 == 1:
        return False
    candidates = [blob]
    if "-" in blob or "_" in blob:
        candidates.append(blob.replace("-", "+").replace("_", "/"))
    for candidate in candidates:
        try:
            raw = base64.b64decode(candidate + "=" * (-len(candidate) % 4), validate=True)
        except Exception:
            continue
        if not raw:
            continue
        printable = sum(1 for b in raw if 32 <= b < 127)
        if printable / len(raw) >= _B64_PRINTABLE_RATIO:
            return True
    return False


def _find_base64(text: str) -> list:
    """Long base64 blobs that decode into readable text."""
    hits = []
    for m in _B64_RUN.finditer(text):
        blob = m.group(0)
        if _decodes_to_text(blob):
            hits.append(Match("encoded-payload", "encoding", m.span(),
                              0.40, blob[:32] + "…",
                              "long base64 blob that decodes to readable text"))
    return hits


def _find_delimiters(text: str) -> list:
    """Delimiter breaking: runs of ```` ``` ````, ``---``, ``###`` … trying
    to escape the document framing. One run is formatting; two or more look
    like fence stuffing."""
    runs = list(_FENCE_RUN.finditer(text))
    if len(runs) < 2:
        return []
    hits = []
    for m in runs:
        token = m.group(0)
        hits.append(Match("delimiter-breaking", "delimiter-breaking", m.span(),
                          WEIGHT_DELIMITER, token,
                          f"{len(runs)} delimiter run(s) in one document"))
    return hits


def _find_phrases(text: str) -> list:
    hits = []
    seen: set = set()
    for rule in PHRASE_RULES:
        for pattern in rule.patterns:
            for m in pattern.finditer(text):
                if (rule.id, m.span()) in seen:  # overlapping spellings of one phrase
                    continue
                seen.add((rule.id, m.span()))
                hits.append(Match(rule.id, rule.family, m.span(), rule.weight, m.group(0)))
    return hits


def _score(matches: list) -> float:
    """First hit of a rule weighs full, every further hit half."""
    per_rule: dict = {}
    for m in matches:
        per_rule.setdefault(m.rule, []).append(m)
    total = 0.0
    for hits in per_rule.values():
        weight = hits[0].weight
        for k in range(len(hits)):
            total += weight * (0.5 ** k)
    return min(1.0, total)


def detect(text: str) -> Detection:
    """Run every heuristic over untrusted text and return a Detection.

    Phrase matching runs on a confusable-folded copy of the text (the fold
    is 1:1, so spans and snippets stay valid), which is how \"іgnore\" with
    a Cyrillic і still gets caught as an instruction override."""
    if not text.strip():
        return Detection(0.0, [], "clean")

    matches = _find_confusables(text) + _find_invisible(text)
    folded = fold_to_ascii(text)
    matches += _find_phrases(folded)
    matches += _find_base64(folded)
    matches += _find_delimiters(folded)

    matches.sort(key=lambda m: (m.span[0], -(m.span[1] - m.span[0])))
    return Detection(_score(matches), matches)
