"""
test_protected_terms.py
-----------------------
Tests asserting that NO detector in the pipeline can claim or mutate protected terminology.
"""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from detectors import DETECTORS, PROTECTED_PHRASES


def test_protected_phrases_complete_immunity():
    test_terms = [
        "The Offer",
        "Offer",
        "Company",
        "our Company",
        "Equity Shares",
        "Capital Structure",
        "Offer Price",
        "Book Building Process",
        "Independent Director",
        "Promoter Trusts",
        "Companies Act, 1956",
        "Companies Act, 2013",
        "SEBI ICDR Regulations",
        "Return on Capital Employed",
        "Revenue from Operations",
        "Financial Statements",
    ]

    for term in test_terms:
        for detector in DETECTORS:
            matches = detector.detect_in_segment("seg_protected", term)
            assert len(matches) == 0, (
                f"Detector {detector.__class__.__name__} falsely claimed protected phrase '{term}'!"
            )
