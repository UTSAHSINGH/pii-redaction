"""
test_company_filter.py
----------------------
Tests for strict COMPANY detection: requires full organization spans with legal corporate suffixes.
"""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from detectors import CompanyDetector


@pytest.fixture
def detector():
    return CompanyDetector()


def test_full_corporate_name(detector):
    text = "References to our Company are to KSH International Limited."
    matches = detector.detect_in_segment("seg_1", text)
    assert len(matches) == 1
    assert matches[0].text == "KSH International Limited"


def test_private_limited(detector):
    text = "KSH International Private Limited was incorporated in 1979."
    matches = detector.detect_in_segment("seg_1", text)
    assert len(matches) == 1
    assert matches[0].text == "KSH International Private Limited"


def test_known_brlm_institution(detector):
    text = "The Book Running Lead Manager is ICICI Securities Limited."
    matches = detector.detect_in_segment("seg_1", text)
    assert len(matches) == 1
    assert matches[0].text == "ICICI Securities Limited"


def test_generic_company_words_not_detected(detector):
    bad_phrases = [
        "Company",
        "the Company",
        "our Company",
        "The Company",
        "Our Company",
        "The Offer",
        "Offer",
        "Companies Act, 1956",
        "Companies Act, 2013",
    ]
    for phrase in bad_phrases:
        matches = detector.detect_in_segment("seg_test", phrase)
        assert len(matches) == 0, f"'{phrase}' must NEVER be detected as COMPANY."
