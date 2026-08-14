"""
detectors package exports for PII Shield.
"""

from detectors.address import AddressDetector
from detectors.base import DetectionContext, PIIDetector, get_context_snippet, luhn_checksum
from detectors.company import CompanyDetector
from detectors.custom import CustomIdentifierDetector
from detectors.dob import DOBDetector
from detectors.person import PersonDetector
from detectors.registry import DEFAULT_REGISTRY, DetectorRegistry
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
from domain_packs import DOMAIN_PACKS, build_protected_regex, get_combined_protected_phrases

ENABLE_ENTITY_PROPAGATION = False
PROTECTED_PHRASES = DOMAIN_PACKS["generic"] | DOMAIN_PACKS["legal"] | DOMAIN_PACKS["finance"]

# Compile global protected regex helper
_PROTECTED_REGEX = build_protected_regex(PROTECTED_PHRASES)


def _get_protected_spans(text: str):
    return [(m.start(), m.end()) for m in _PROTECTED_REGEX.finditer(text)]


def _overlaps_protected(start: int, end: int, protected_spans):
    for p_start, p_end in protected_spans:
        if start < p_end and p_start < end:
            return True
    return False


DETECTORS = DEFAULT_REGISTRY._standard_detectors

__all__ = [
    "AddressDetector",
    "CompanyDetector",
    "CreditCardDetector",
    "CustomIdentifierDetector",
    "DEFAULT_REGISTRY",
    "DETECTORS",
    "DOBDetector",
    "DetectionContext",
    "DetectorRegistry",
    "EMAIL",
    "ENABLE_ENTITY_PROPAGATION",
    "EmailDetector",
    "IBANDetector",
    "IPAddressDetector",
    "PANDetector",
    "PIIDetector",
    "PROTECTED_PHRASES",
    "PersonDetector",
    "PhoneDetector",
    "SSNDetector",
    "UPIDetector",
    "_get_protected_spans",
    "_overlaps_protected",
    "get_context_snippet",
    "luhn_checksum",
]
