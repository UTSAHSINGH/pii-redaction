"""
utils.py
--------
Shared utilities: dataclasses, logging setup, overlap resolution, span validation,
Luhn algorithm, and JSON helpers.
"""

from __future__ import annotations

import json
import logging
import hashlib
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logger(name: str = "pii_redactor", level: int = logging.INFO) -> logging.Logger:
    """Return a configured logger with both stream and file handlers."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(level)
    fmt = logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    return logger


log = setup_logger()


# ---------------------------------------------------------------------------
# Core Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class PIIMatch:
    """Represents a single detected PII span within a DocumentSegment."""

    segment_id: str           # Unique identifier of the containing DocumentSegment
    entity_type: str          # e.g. "EMAIL", "PHONE", "PERSON", "COMPANY", "ADDRESS"
    start: int                # Start character index within the segment's text (0-based)
    end: int                  # End character index (exclusive)
    text: str                 # Exact original substring segment.text[start:end]
    confidence: float         # Confidence score between 0.0 and 1.0
    source: str = "regex"     # Detection source: "regex" | "ner" | "context" | "propagation"
    context: str = ""         # Surrounding context snippet for audit logging
    replacement: Optional[str] = None  # Synthetic replacement string

    def __post_init__(self) -> None:
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be in [0, 1], got {self.confidence}")
        if self.start < 0 or self.end < self.start:
            raise ValueError(f"Invalid span [{self.start}:{self.end}] for text '{self.text}'")

    def span_key(self) -> Tuple[int, int]:
        return (self.start, self.end)

    def overlaps(self, other: "PIIMatch") -> bool:
        """Return True if this span overlaps with another in the same segment."""
        if self.segment_id != other.segment_id:
            return False
        return self.start < other.end and other.start < self.end

    def contains(self, other: "PIIMatch") -> bool:
        """Return True if this span completely covers another in the same segment."""
        if self.segment_id != other.segment_id:
            return False
        return self.start <= other.start and self.end >= other.end

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Span Validation
# ---------------------------------------------------------------------------

def validate_match_span(match: PIIMatch, segment_text: str) -> bool:
    """
    Strict validation: ensures that segment_text[match.start:match.end] exactly
    equals match.text. If there is any offset mismatch, reject the match.
    """
    if match.start < 0 or match.end > len(segment_text):
        log.warning(
            "Span boundary out of range in segment '%s': [%d:%d] vs text length %d",
            match.segment_id, match.start, match.end, len(segment_text)
        )
        return False

    actual_substring = segment_text[match.start:match.end]
    if actual_substring != match.text:
        log.warning(
            "Span text mismatch in segment '%s': expected '%s', found '%s' at [%d:%d]",
            match.segment_id, match.text, actual_substring, match.start, match.end
        )
        return False

    return True


# ---------------------------------------------------------------------------
# Overlap Resolution
# ---------------------------------------------------------------------------

# Strict priority rank for entity types (lower number = higher priority)
_ENTITY_PRIORITY = {
    "CREDIT_CARD": 1,
    "EMAIL":       2,
    "PHONE":       3,
    "SSN":         4,
    "IP_ADDRESS":  5,
    "DOB":         6,
    "PAN":         7,
    "UPI_ID":      8,
    "ADDRESS":     9,
    "PERSON":      10,
    "COMPANY":     11,
}


def resolve_overlaps(matches: List[PIIMatch]) -> List[PIIMatch]:
    """
    Deterministic overlap resolution for matches within segments.
    Groups matches by segment_id, then resolves overlaps greedily:
      1. Higher entity type priority (structured PII > contextual > NER)
      2. Higher confidence
      3. Longer span (more specific)
      4. Earlier start
    """
    if not matches:
        return []

    # Group by segment_id
    by_segment: Dict[str, List[PIIMatch]] = {}
    for m in matches:
        by_segment.setdefault(m.segment_id, []).append(m)

    accepted_all: List[PIIMatch] = []

    for segment_id, seg_matches in by_segment.items():
        # Sort candidates
        sorted_matches = sorted(
            seg_matches,
            key=lambda m: (
                _ENTITY_PRIORITY.get(m.entity_type, 99),
                -m.confidence,
                -(m.end - m.start),
                m.start,
            ),
        )

        accepted_seg: List[PIIMatch] = []
        for candidate in sorted_matches:
            # Check overlap against already accepted matches in this segment
            has_overlap = False
            for accepted in accepted_seg:
                if candidate.overlaps(accepted):
                    has_overlap = True
                    break
            if not has_overlap:
                accepted_seg.append(candidate)

        # Sort accepted matches by start index ASC
        accepted_seg.sort(key=lambda m: m.start)
        accepted_all.extend(accepted_seg)

    return accepted_all


# ---------------------------------------------------------------------------
# Luhn Algorithm (Credit Card Validation & Generation)
# ---------------------------------------------------------------------------

def luhn_checksum(card_number: str) -> bool:
    """Verify card_number passes the Luhn (mod-10) checksum algorithm."""
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    double = False
    for d in reversed(digits):
        if double:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        double = not double
    return (total % 10) == 0


def luhn_generate(prefix: str, length: int) -> str:
    """Generate a valid Luhn number with the given prefix and total length."""
    partial = list(prefix)
    while len(partial) < length - 1:
        partial.append(str((len(partial) * 3 + 7) % 10))
    digits = [int(d) for d in partial]
    total = 0
    double = True  # double every second from right
    for d in reversed(digits):
        if double:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        double = not double
    check = (10 - (total % 10)) % 10
    partial.append(str(check))
    return "".join(partial)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_context_snippet(text: str, start: int, end: int, window: int = 40) -> str:
    """Extract a surrounding snippet around a match for audit logging."""
    s = max(0, start - window)
    e = min(len(text), end + window)
    snippet = text[s:e].replace("\n", " ").replace("\r", " ")
    return snippet.strip()


def hash_text(text: str) -> str:
    """Deterministic 16-character SHA-256 prefix of text for privacy-safe logs."""
    return hashlib.sha256(text.strip().encode("utf-8")).hexdigest()[:16]


def save_json(data: object, path: str | Path) -> None:
    """Write data as formatted JSON with UTF-8 encoding."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    log.info("Saved JSON → %s", p)
