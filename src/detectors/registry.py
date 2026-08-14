"""
registry.py
-----------
Detector Registry for PII Shield.
Instantiates, configures, and orchestrates all built-in and custom PII detectors.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Set

from detectors.address import AddressDetector
from detectors.base import DetectionContext, PIIDetector
from detectors.company import CompanyDetector
from detectors.custom import CustomIdentifierDetector
from detectors.dob import DOBDetector
from detectors.person import PersonDetector
from detectors.structured import (
    CreditCardDetector,
    EmailDetector,
    IBANDetector,
    IPAddressDetector,
    PANDetector,
    PhoneDetector,
    SSNDetector,
    UPIDetector,
)
from domain_packs import build_protected_regex, get_combined_protected_phrases
from models import DetectionConfig, DocumentSegment, PIIMatch

log = logging.getLogger("pii_shield")


class DetectorRegistry:
    """Central registry of PII detectors with runtime configuration support."""

    def __init__(self) -> None:
        self._standard_detectors: List[PIIDetector] = [
            EmailDetector(),
            PhoneDetector(),
            CreditCardDetector(),
            SSNDetector(),
            IPAddressDetector(),
            PANDetector(),
            UPIDetector(),
            IBANDetector(),
            PersonDetector(),
            CompanyDetector(),
            AddressDetector(),
            DOBDetector(),
        ]

    def scan_segments(
        self,
        segments: List[DocumentSegment],
        config: DetectionConfig,
    ) -> List[PIIMatch]:
        """Scan a list of document segments using the provided configuration."""
        # 1. Build protected domain phrases and regex
        protected_phrases = get_combined_protected_phrases(
            config.domain_packs, config.custom_protected_terms
        )
        protected_regex = build_protected_regex(protected_phrases)

        context = DetectionContext(
            enabled_categories=set(config.enabled_categories),
            protected_regex=protected_regex,
            protected_phrases=protected_phrases,
            auto_redact_threshold=config.auto_redact_threshold,
        )

        # 2. Collect active detectors
        active_detectors: List[PIIDetector] = []
        for d in self._standard_detectors:
            if d.entity_type in context.enabled_categories:
                active_detectors.append(d)

        # 3. Add custom detectors
        for c in config.custom_detectors:
            active_detectors.append(CustomIdentifierDetector(c))

        # 4. Execute detection across segments
        all_matches: List[PIIMatch] = []
        for seg in segments:
            if not seg.text.strip():
                continue
            for detector in active_detectors:
                try:
                    matches = detector.detect(seg, context)
                    for m in matches:
                        # Auto-approve if high confidence; flag for review if medium
                        m.approved = m.confidence >= config.auto_redact_threshold
                        all_matches.append(m)
                except Exception as exc:
                    log.error("Detector %s failed on segment %s: %s", detector.entity_type, seg.segment_id, exc)

        return all_matches


# Global default registry instance
DEFAULT_REGISTRY = DetectorRegistry()
