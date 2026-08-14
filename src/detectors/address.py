"""
address.py
----------
General-Purpose, Multi-Signal ADDRESS Detector.
Detects complete physical and mailing address blocks using:
1. Address context markers (Address, Registered Office, Corporate Office, Mailing Address, etc.)
2. Structural street keywords (Street, Road, Ave, Suite, Floor, Plot, Sector, Gat, Flat, Tower, etc.)
3. Postal / PIN codes (5-6 digit PINs, US ZIP codes, UK postal codes)
4. Multi-line address blocks.
CRITICAL: Standalone geographic city/country names (e.g. 'Pune', 'Mumbai', 'London', 'India') are NEVER redacted alone.
"""

from __future__ import annotations

import logging
from typing import List, Set, Tuple
import uuid

import regex

from detectors.base import DetectionContext, PIIDetector, get_context_snippet
from models import ConfidenceTier, DocumentSegment, PIIMatch

log = logging.getLogger("pii_shield")


class AddressDetector(PIIDetector):
    """General-purpose multi-signal ADDRESS detector."""

    entity_type = "ADDRESS"

    # Context labels indicating an address block
    _LABEL_PATTERN = regex.compile(
        r"\b(?:"
        r"Registered\s+Office(?:\s+and\s+Corporate\s+Office)?(?:\s+at)?"
        r"|Corporate\s+Office(?:\s+at)?"
        r"|Headquarters(?:\s+at)?"
        r"|Head\s+Office(?:\s+at)?"
        r"|Branch\s+Office(?:\s+at)?"
        r"|Plant(?:\s+(?:I|II|III|IV|V|\d+))?(?:\s+at)?"
        r"|Manufacturing\s+Facility(?:\s+at)?"
        r"|Facility(?:\s+at)?"
        r"|Unit\s+(?:I|II|III|\d+)(?:\s+at)?"
        r"|Mailing\s+Address"
        r"|Residential\s+Address"
        r"|Delivery\s+Address"
        r"|Billing\s+Address"
        r"|Shipping\s+Address"
        r"|Permanent\s+Address"
        r"|Present\s+Address"
        r"|Address"
        r")\s*[:\-]\s*",
        regex.IGNORECASE,
    )

    # Street keywords & structural markers
    _STREET_MARKERS = (
        r"(?:Plot|Gat|Survey|CTS|Sector|Block|Phase|Flat|Apartment|Apt\.?|Suite|Room|Floor|Level|Tower|Building|"
        r"Industrial\s+Area|Village|Taluka|District|P\.?O\.?\s*Box|Post\s+Box|"
        r"Street|St\.?|Road|Rd\.?|Avenue|Ave\.?|Boulevard|Blvd\.?|Lane|Ln\.?|Drive|Dr\.?|Way|Court|Ct\.?|Square|Sq\.?)"
    )

    # Postal code pattern (India 6-digit PIN, US 5-digit ZIP, UK Postal)
    _POSTAL_PATTERN = r"(?:[\d]{3}\s*[\d]{3}|[\d]{5}(?:-\d{4})?|[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2})"

    # Content pattern after label
    _CONTENT_AFTER_LABEL = regex.compile(
        rf"(?:[A-Za-z0-9\/\.,\-\s–#]{{10,250}}?(?:{_POSTAL_PATTERN}|Maharashtra|Gujarat|Karnataka|Tamil\s+Nadu|Delhi|India|USA|UK|United\s+States|United\s+Kingdom|California|New\s+York|London|Bengaluru|Mumbai|Pune|Texas|Ontario|Canada))(?=\.|\s+Telephone|\s+Tel|\s+Phone|\s+CIN|\s+Email|\n|$)",
        regex.IGNORECASE,
    )

    # Standalone structural street address pattern (e.g. "1600 Pennsylvania Avenue NW, Washington DC 20500")
    _STRUCTURAL_ADDRESS = regex.compile(
        rf"\b\d{{1,5}}[\s\-\/]+[A-Za-z0-9\s\.,]{{5,60}}?\s+{_STREET_MARKERS}\b[^\n;\.]{{5,120}}?(?:{_POSTAL_PATTERN})\b",
        regex.IGNORECASE,
    )

    def detect(self, segment: DocumentSegment, context: DetectionContext) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        text = segment.text
        seen_spans: Set[Tuple[int, int]] = set()

        # 1. Address blocks starting from label markers (HIGH confidence: 0.94)
        for label_m in self._LABEL_PATTERN.finditer(text):
            label_end = label_m.end()
            content_m = self._CONTENT_AFTER_LABEL.match(text, label_end)
            if content_m:
                start = content_m.start()
                end = content_m.end()
                raw = text[start:end].strip()
                if not context.is_protected(text, start, end) and len(raw) >= 12:
                    span = (start, end)
                    seen_spans.add(span)
                    results.append(PIIMatch(
                        match_id=str(uuid.uuid4()),
                        segment_id=segment.segment_id,
                        entity_type=self.entity_type,
                        start=start,
                        end=end,
                        text=raw,
                        confidence=0.94,
                        confidence_tier=ConfidenceTier.HIGH,
                        source="address_label_block",
                        context=get_context_snippet(text, start, end),
                    ))

        # 2. Structural street address pattern (HIGH confidence: 0.91)
        for struct_m in self._STRUCTURAL_ADDRESS.finditer(text):
            start = struct_m.start()
            end = struct_m.end()
            raw = struct_m.group(0).strip()
            if not context.is_protected(text, start, end):
                span = (start, end)
                if not any(s <= start and end <= e for s, e in seen_spans):
                    seen_spans.add(span)
                    results.append(PIIMatch(
                        match_id=str(uuid.uuid4()),
                        segment_id=segment.segment_id,
                        entity_type=self.entity_type,
                        start=start,
                        end=end,
                        text=raw,
                        confidence=0.91,
                        confidence_tier=ConfidenceTier.HIGH,
                        source="structural_address",
                        context=get_context_snippet(text, start, end),
                    ))

        return results
