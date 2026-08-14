"""
company.py
----------
General-Purpose COMPANY / ORGANIZATION Detector.
Detects complete corporate entity spans ending in legal entity suffixes or preceded by business context.
Zero hardcoded company names.
"""

from __future__ import annotations

import logging
from typing import List, Set, Tuple
import uuid

import regex

from detectors.base import DetectionContext, PIIDetector, get_context_snippet
from models import ConfidenceTier, DocumentSegment, PIIMatch

log = logging.getLogger("pii_shield")


class CompanyDetector(PIIDetector):
    """General-purpose COMPANY / ORGANIZATION detector."""

    entity_type = "COMPANY"

    # Matches complete organization spans ending with legal suffix
    _COMPANY_SUFFIX_PATTERN = regex.compile(
        r"\b(?:[A-Z][a-zA-Z0-9&'\.\-]+\s+){1,6}"
        r"(?:Private\s+Limited|Pvt\.?\s*Ltd\.?|Limited|Ltd\.?|LLP|Inc\.?|Corporation|Corp\.?|LLC|GmbH|S\.?A\.?|A\.?G\.?|Holdings?)\b",
        regex.IGNORECASE,
    )

    _CONTEXT_LABELS = regex.compile(
        r"\b(?:"
        r"Employer"
        r"|Company(?:\s+Name)?"
        r"|Organization"
        r"|Vendor(?:\s+Name)?"
        r"|Client(?:\s+Name)?"
        r"|Contractor"
        r"|Customer(?:\s+Company)?"
        r"|Bank(?:\s+Name)?"
        r"|Registrar(?:\s+to\s+the\s+Offer)?"
        r"|Statutory\s+Auditor"
        r"|Book\s+Running\s+Lead\s+Manager"
        r"|BRLM"
        r"|Lead\s+Manager"
        r")\s*[:\-]?\s*",
        regex.IGNORECASE,
    )

    _LEADING_STOPWORDS = {
        "the", "our", "an", "a", "is", "are", "to", "by", "for", "from", "in", "on", "at",
        "with", "as", "issuer", "company", "to", "of", "and", "or", "references",
    }

    _FORBIDDEN_COMPANY_TOKENS = {
        "the company", "our company", "the offer", "the issue", "companies act", "sebi",
        "equity shares", "capital structure", "return on capital", "revenue from operations",
        "independent director", "promoter group", "promoter trust", "statutory auditor",
        "terms and conditions", "privacy policy", "table of contents", "executive summary",
    }

    def detect(self, segment: DocumentSegment, context: DetectionContext) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        text = segment.text
        seen_spans: Set[Tuple[int, int]] = set()

        # 1. Business Context Label matching (HIGH confidence: 0.95)
        for ctx_m in self._CONTEXT_LABELS.finditer(text):
            window_start = ctx_m.end()
            window = text[window_start: min(len(text), window_start + 100)]
            org_m = regex.search(r"\b(?:[A-Z][a-zA-Z0-9&'\.\-]+\s+){1,5}(?:Private\s+Limited|Pvt\.?\s*Ltd\.?|Limited|Ltd\.?|LLP|Inc\.?|Corporation|Corp\.?|LLC|Bank|Securities|Solutions|Services)\b", window)
            if org_m:
                start = window_start + org_m.start()
                end = window_start + org_m.end()
                raw = text[start:end].strip()
                if not context.is_protected(text, start, end):
                    span = (start, end)
                    seen_spans.add(span)
                    results.append(PIIMatch(
                        match_id=str(uuid.uuid4()),
                        segment_id=segment.segment_id,
                        entity_type=self.entity_type,
                        start=start,
                        end=end,
                        text=raw,
                        confidence=0.95,
                        confidence_tier=ConfidenceTier.HIGH,
                        source="company_context",
                        context=get_context_snippet(text, start, end),
                    ))

        # 2. Strict legal suffix corporate patterns (HIGH confidence: 0.90)
        for m in self._COMPANY_SUFFIX_PATTERN.finditer(text):
            start = m.start()
            end = m.end()
            raw = text[start:end].strip()

            # Strip leading stopwords
            words = raw.split()
            while len(words) > 2 and words[0].lower() in self._LEADING_STOPWORDS:
                lead_word = words.pop(0)
                m_lead = regex.search(rf"\b{regex.escape(lead_word)}\b\s*", text[start:end], regex.IGNORECASE)
                if m_lead:
                    start += m_lead.end()
                raw = text[start:end].strip()

            if context.is_protected(text, start, end):
                continue
            if raw.lower() in self._FORBIDDEN_COMPANY_TOKENS:
                continue

            words = raw.split()
            if len(words) < 2 or not raw[0].isupper():
                continue
            if any(w.lower() in {"act", "section", "rule", "regulation", "schedule"} for w in words):
                continue

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
                    confidence=0.90,
                    confidence_tier=ConfidenceTier.HIGH,
                    source="regex_suffix",
                    context=get_context_snippet(text, start, end),
                ))

        return results
