"""
base.py
-------
Abstract base detector protocol, detection context, and utility helpers for PII Shield.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid
import regex

from models import ConfidenceTier, DocumentSegment, PIIMatch


@dataclass
class DetectionContext:
    """Shared runtime context passed to all detectors during document scanning."""
    enabled_categories: Set[str] = field(default_factory=set)
    protected_regex: Optional[regex.Pattern] = None
    protected_phrases: Set[str] = field(default_factory=set)
    auto_redact_threshold: float = 0.85
    custom_rules: List[Any] = field(default_factory=list)

    def is_protected(self, text: str, start: int, end: int) -> bool:
        """Check if character span [start:end] in text overlaps with protected domain vocabulary."""
        if not self.protected_regex:
            return False
        span_text = text[start:end]
        if self.protected_regex.fullmatch(span_text.strip()):
            return True
        for m in self.protected_regex.finditer(text):
            p_start, p_end = m.start(), m.end()
            if start < p_end and p_start < end:
                return True
        return False


def get_context_snippet(text: str, start: int, end: int, window: int = 40) -> str:
    """Return a contextual snippet around the matched span."""
    s = max(0, start - window)
    e = min(len(text), end + window)
    prefix = ("..." if s > 0 else "") + text[s:start]
    target = text[start:end]
    suffix = text[end:e] + ("..." if e < len(text) else "")
    return f"{prefix}[{target}]{suffix}".strip()


def luhn_checksum(card_number_digits: str) -> bool:
    """Validate credit card number using Luhn mod-10 algorithm."""
    digits = [int(c) for c in card_number_digits if c.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


class PIIDetector(ABC):
    """Abstract interface for all PII detectors."""

    entity_type: str = "GENERIC"

    @abstractmethod
    def detect(self, segment: DocumentSegment, context: DetectionContext) -> List[PIIMatch]:
        """Detect candidate PII instances within a document segment."""
        pass

    def detect_in_segment(self, segment_id: str, text: str) -> List[PIIMatch]:
        """Convenience method for segment detection with default context."""
        seg = DocumentSegment(segment_id=segment_id, text=text)
        from domain_packs import build_protected_regex, DOMAIN_PACKS
        phrases = DOMAIN_PACKS["generic"] | DOMAIN_PACKS["legal"] | DOMAIN_PACKS["finance"]
        ctx = DetectionContext(
            enabled_categories={self.entity_type},
            protected_regex=build_protected_regex(phrases),
            protected_phrases=phrases,
        )
        return self.detect(seg, ctx)
