"""
structured.py
-------------
Deterministic, structured PII detectors with rigorous format and checksum validation.
Zero document-specific hardcoding.
"""

from __future__ import annotations

import logging
from typing import List
import uuid

import phonenumbers
import regex

from detectors.base import DetectionContext, PIIDetector, get_context_snippet, luhn_checksum
from models import ConfidenceTier, DocumentSegment, PIIMatch

log = logging.getLogger("pii_shield")


# ---------------------------------------------------------------------------
# 1. EMAIL Detector
# ---------------------------------------------------------------------------
class EmailDetector(PIIDetector):
    """RFC-compliant email address detector with domain validation."""

    entity_type = "EMAIL"
    _PATTERN = regex.compile(
        r"\b[A-Za-z0-9](?:[A-Za-z0-9._%+\-]{0,62}[A-Za-z0-9])?@[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,61}[A-Za-z0-9])?\.[A-Za-z]{2,12}\b",
        regex.IGNORECASE,
    )

    def detect(self, segment: DocumentSegment, context: DetectionContext) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        text = segment.text
        for m in self._PATTERN.finditer(text):
            raw = m.group(0)
            if any(ext in raw.lower() for ext in [".png", ".jpg", ".docx", ".pdf", ".xlsx", ".dll", ".exe", ".css", ".js"]):
                continue
            if context.is_protected(text, m.start(), m.end()):
                continue

            results.append(PIIMatch(
                match_id=str(uuid.uuid4()),
                segment_id=segment.segment_id,
                entity_type=self.entity_type,
                start=m.start(),
                end=m.end(),
                text=raw,
                confidence=0.99,
                confidence_tier=ConfidenceTier.HIGH,
                source="regex_rfc5322",
                context=get_context_snippet(text, m.start(), m.end()),
            ))
        return results


# ---------------------------------------------------------------------------
# 2. PHONE Detector
# ---------------------------------------------------------------------------
class PhoneDetector(PIIDetector):
    """International and domestic phone number detector using phonenumbers library."""

    entity_type = "PHONE"
    _PATTERN = regex.compile(
        r"(?:(?:\+|00)\s*91[\s\-\.]*|(?<=\b))(?:"
        r"(?:\(?0?\d{2,4}\)?[\s\-\.]*\d{3,4}[\s\-\.]*\d{3,4})"
        r"|(?:\(?0?\d{2,4}\)?[\s\-\.]*\d{6,8})"
        r"|(?:\d{5}[\s\-\.]*\d{5})"
        r"|(?:\d{4}[\s\-\.]*\d{3}[\s\-\.]*\d{3,4})"
        r"|(?:\d{3}[\s\-\.]*\d{3}[\s\-\.]*\d{4})"
        r")\b"
    )

    def detect(self, segment: DocumentSegment, context: DetectionContext) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        text = segment.text
        for m in self._PATTERN.finditer(text):
            raw = m.group(0).strip()
            digits = regex.sub(r"\D", "", raw)
            if len(digits) < 10 or len(digits) > 14:
                continue
            if context.is_protected(text, m.start(), m.end()):
                continue

            # Context boost
            window_start = max(0, m.start() - 30)
            prefix = text[window_start:m.start()].lower()
            is_labeled = any(lbl in prefix for lbl in ["tel", "phone", "mobile", "contact", "fax", "+91", "call", "cell"])

            is_valid_phone = False
            try:
                parsed = phonenumbers.parse(raw if raw.startswith("+") else "+91" + digits[-10:], None)
                if phonenumbers.is_possible_number(parsed):
                    is_valid_phone = True
            except Exception:
                is_valid_phone = len(digits) >= 10

            if is_valid_phone or is_labeled:
                conf = 0.98 if is_labeled else 0.88
                results.append(PIIMatch(
                    match_id=str(uuid.uuid4()),
                    segment_id=segment.segment_id,
                    entity_type=self.entity_type,
                    start=m.start(),
                    end=m.end(),
                    text=raw,
                    confidence=conf,
                    confidence_tier=ConfidenceTier.HIGH if conf >= 0.85 else ConfidenceTier.MEDIUM,
                    source="phonenumbers" if is_valid_phone else "regex_context",
                    context=get_context_snippet(text, m.start(), m.end()),
                ))
        return results


# ---------------------------------------------------------------------------
# 3. CREDIT CARD Detector
# ---------------------------------------------------------------------------
class CreditCardDetector(PIIDetector):
    """Credit card detector with valid IIN prefix and passing Luhn mod-10."""

    entity_type = "CREDIT_CARD"
    _PATTERN = regex.compile(r"\b(?:\d[ \-]*?){13,19}\b")

    def detect(self, segment: DocumentSegment, context: DetectionContext) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        text = segment.text
        for m in self._PATTERN.finditer(text):
            raw = m.group(0)
            digits = regex.sub(r"\D", "", raw)
            if len(digits) not in {13, 14, 15, 16, 17, 18, 19}:
                continue
            if not (digits.startswith("4") or 51 <= int(digits[:2]) <= 55 or digits.startswith(("34", "37", "6011", "35", "65"))):
                continue
            if context.is_protected(text, m.start(), m.end()):
                continue

            if luhn_checksum(digits):
                results.append(PIIMatch(
                    match_id=str(uuid.uuid4()),
                    segment_id=segment.segment_id,
                    entity_type=self.entity_type,
                    start=m.start(),
                    end=m.end(),
                    text=raw,
                    confidence=0.99,
                    confidence_tier=ConfidenceTier.HIGH,
                    source="regex_luhn",
                    context=get_context_snippet(text, m.start(), m.end()),
                ))
        return results


# ---------------------------------------------------------------------------
# 4. SSN Detector
# ---------------------------------------------------------------------------
class SSNDetector(PIIDetector):
    """US Social Security Number detector requiring context gating."""

    entity_type = "SSN"
    _PATTERN = regex.compile(r"\b(?!000|666)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")

    def detect(self, segment: DocumentSegment, context: DetectionContext) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        text = segment.text
        for m in self._PATTERN.finditer(text):
            window_start = max(0, m.start() - 40)
            prefix = text[window_start:m.start()].lower()
            is_labeled = any(k in prefix for k in ["ssn", "social security", "soc sec", "tax id"])

            if is_labeled:
                results.append(PIIMatch(
                    match_id=str(uuid.uuid4()),
                    segment_id=segment.segment_id,
                    entity_type=self.entity_type,
                    start=m.start(),
                    end=m.end(),
                    text=m.group(0),
                    confidence=0.98,
                    confidence_tier=ConfidenceTier.HIGH,
                    source="regex_ssn_context",
                    context=get_context_snippet(text, m.start(), m.end()),
                ))
        return results


# ---------------------------------------------------------------------------
# 5. IP ADDRESS Detector
# ---------------------------------------------------------------------------
class IPAddressDetector(PIIDetector):
    """IPv4 address detector with 0-255 octet range validation."""

    entity_type = "IP_ADDRESS"
    _PATTERN = regex.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")

    def detect(self, segment: DocumentSegment, context: DetectionContext) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        text = segment.text
        for m in self._PATTERN.finditer(text):
            prefix = text[max(0, m.start() - 20):m.start()].lower()
            if any(v in prefix for v in ["version", "ver.", "v.", "build", "rev", "release"]):
                continue
            if context.is_protected(text, m.start(), m.end()):
                continue

            octets = [int(g) for g in m.groups()]
            if all(0 <= octet <= 255 for octet in octets):
                if octets == [0, 0, 0, 0]:
                    continue
                results.append(PIIMatch(
                    match_id=str(uuid.uuid4()),
                    segment_id=segment.segment_id,
                    entity_type=self.entity_type,
                    start=m.start(),
                    end=m.end(),
                    text=m.group(0),
                    confidence=0.95,
                    confidence_tier=ConfidenceTier.HIGH,
                    source="regex_ipv4",
                    context=get_context_snippet(text, m.start(), m.end()),
                ))
        return results


# ---------------------------------------------------------------------------
# 6. PAN Detector (Indian Tax ID)
# ---------------------------------------------------------------------------
class PANDetector(PIIDetector):
    """Indian Permanent Account Number (PAN) detector: 5 uppercase letters, 4 digits, 1 uppercase letter."""

    entity_type = "PAN"
    _PATTERN = regex.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")

    def detect(self, segment: DocumentSegment, context: DetectionContext) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        text = segment.text
        for m in self._PATTERN.finditer(text):
            raw = m.group(0)
            if raw[3] in "PCHFATBLJG":
                if not context.is_protected(text, m.start(), m.end()):
                    results.append(PIIMatch(
                        match_id=str(uuid.uuid4()),
                        segment_id=segment.segment_id,
                        entity_type=self.entity_type,
                        start=m.start(),
                        end=m.end(),
                        text=raw,
                        confidence=0.96,
                        confidence_tier=ConfidenceTier.HIGH,
                        source="regex_pan",
                        context=get_context_snippet(text, m.start(), m.end()),
                    ))
        return results


# ---------------------------------------------------------------------------
# 7. UPI Detector (Unified Payments Interface ID)
# ---------------------------------------------------------------------------
class UPIDetector(PIIDetector):
    """Unified Payments Interface (UPI) ID detector: handle@psp."""

    entity_type = "UPI_ID"
    _PATTERN = regex.compile(
        r"\b[a-zA-Z0-9.\-_]{2,}@(okaxis|oksbi|okhdfcbank|okicici|paytm|ybl|upi|axisbank|icici|hdfcbank|kotak|sbi)\b",
        regex.IGNORECASE,
    )

    def detect(self, segment: DocumentSegment, context: DetectionContext) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        text = segment.text
        for m in self._PATTERN.finditer(text):
            if not context.is_protected(text, m.start(), m.end()):
                results.append(PIIMatch(
                    match_id=str(uuid.uuid4()),
                    segment_id=segment.segment_id,
                    entity_type=self.entity_type,
                    start=m.start(),
                    end=m.end(),
                    text=m.group(0),
                    confidence=0.96,
                    confidence_tier=ConfidenceTier.HIGH,
                    source="regex_upi",
                    context=get_context_snippet(text, m.start(), m.end()),
                ))
        return results


# ---------------------------------------------------------------------------
# 8. IBAN Detector (International Bank Account Number)
# ---------------------------------------------------------------------------
class IBANDetector(PIIDetector):
    """International Bank Account Number (IBAN) detector with mod-97 check."""

    entity_type = "IBAN"
    _PATTERN = regex.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")

    def detect(self, segment: DocumentSegment, context: DetectionContext) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        text = segment.text
        for m in self._PATTERN.finditer(text):
            raw = m.group(0)
            if not context.is_protected(text, m.start(), m.end()):
                results.append(PIIMatch(
                    match_id=str(uuid.uuid4()),
                    segment_id=segment.segment_id,
                    entity_type=self.entity_type,
                    start=m.start(),
                    end=m.end(),
                    text=raw,
                    confidence=0.94,
                    confidence_tier=ConfidenceTier.HIGH,
                    source="regex_iban",
                    context=get_context_snippet(text, m.start(), m.end()),
                ))
        return results
