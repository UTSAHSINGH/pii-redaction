"""
dob.py
------
Context-Gated DATE_OF_BIRTH (DOB) Detector.
Detects birth dates only when immediately preceded by birth context.
Ordinary calendar dates (e.g. 'Dated December 10, 2025', 'March 31, 2024') are NEVER detected.
"""

from __future__ import annotations

import logging
from typing import List
import uuid

import regex

from detectors.base import DetectionContext, PIIDetector, get_context_snippet
from models import ConfidenceTier, DocumentSegment, PIIMatch

log = logging.getLogger("pii_shield")


class DOBDetector(PIIDetector):
    """Context-gated Date of Birth detector."""

    entity_type = "DOB"

    _TRIGGER = regex.compile(
        r"(?:\bdate\s+of\s+birth\b|\bd\s*\.?\s*o\s*\.?\s*b\s*\.?|\bbirth\s*date\b|\bborn\s+on\b|\bborn\b)\s*[:\-]?\s*",
        regex.IGNORECASE,
    )
    _DATE_PATTERN = regex.compile(
        r"(?:\d{1,2}[\/\-\.](?:\d{1,2}|[A-Za-z]{3,9})[\/\-\.]\d{2,4}"
        r"|(?:January|February|March|April|May|June|July|August|September|October|November|December|[A-Za-z]{3})\s+\d{1,2},?\s+\d{4}"
        r"|\d{1,2}(?:st|nd|rd|th)?\s+(?:January|February|March|April|May|June|July|August|September|October|November|December|[A-Za-z]{3}),?\s+\d{4})",
        regex.IGNORECASE,
    )

    def detect(self, segment: DocumentSegment, context: DetectionContext) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        text = segment.text
        for trig in self._TRIGGER.finditer(text):
            trig_end = trig.end()
            date_m = self._DATE_PATTERN.match(text, trig_end)
            if date_m:
                start = date_m.start()
                end = date_m.end()
                raw = date_m.group(0).strip()
                if not context.is_protected(text, start, end):
                    results.append(PIIMatch(
                        match_id=str(uuid.uuid4()),
                        segment_id=segment.segment_id,
                        entity_type=self.entity_type,
                        start=start,
                        end=end,
                        text=raw,
                        confidence=0.98,
                        confidence_tier=ConfidenceTier.HIGH,
                        source="context_gated_dob",
                        context=get_context_snippet(text, start, end),
                    ))
        return results
