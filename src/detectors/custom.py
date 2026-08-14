"""
custom.py
---------
User-Defined Custom Identifier Detector for PII Shield.
Allows users to define custom regular expressions (e.g. Employee ID, Internal Project Code).
"""

from __future__ import annotations

import logging
from typing import List
import uuid

import regex

from detectors.base import DetectionContext, PIIDetector, get_context_snippet
from models import ConfidenceTier, CustomDetectorConfig, DocumentSegment, PIIMatch

log = logging.getLogger("pii_shield")


class CustomIdentifierDetector(PIIDetector):
    """Detector for user-configured custom regex patterns."""

    def __init__(self, config: CustomDetectorConfig) -> None:
        self.entity_type = config.entity_name
        self.confidence = config.confidence
        try:
            self._pattern = regex.compile(config.pattern)
        except Exception as exc:
            log.error("Invalid custom regex pattern '%s': %s", config.pattern, exc)
            self._pattern = None

    def detect(self, segment: DocumentSegment, context: DetectionContext) -> List[PIIMatch]:
        if not self._pattern:
            return []
        results: List[PIIMatch] = []
        text = segment.text
        for m in self._pattern.finditer(text):
            start = m.start()
            end = m.end()
            raw = m.group(0)
            if not context.is_protected(text, start, end):
                results.append(PIIMatch(
                    match_id=str(uuid.uuid4()),
                    segment_id=segment.segment_id,
                    entity_type=self.entity_type,
                    start=start,
                    end=end,
                    text=raw,
                    confidence=self.confidence,
                    confidence_tier=ConfidenceTier.HIGH if self.confidence >= 0.85 else ConfidenceTier.MEDIUM,
                    source="custom_user_regex",
                    context=get_context_snippet(text, start, end),
                ))
        return results
