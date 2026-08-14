"""
test_person_filter.py
---------------------
Tests for strict PERSON filtering: requires salutations, role labels, or known management context.
"""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from detectors import PersonDetector


@pytest.fixture
def detector():
    return PersonDetector()


def test_salutation_prefix(detector):
    text = "Please contact Mr. Sarthak Malvadkar regarding queries."
    matches = detector.detect_in_segment("seg_1", text)
    assert len(matches) == 1
    assert "Sarthak Malvadkar" in matches[0].text


def test_role_context_prefix(detector):
    text = "Company Secretary and Compliance Officer: Sarthak Malvadkar"
    matches = detector.detect_in_segment("seg_1", text)
    assert len(matches) == 1
    assert matches[0].text == "Sarthak Malvadkar"


def test_managing_director_context(detector):
    text = "Managing Director: Kushal Subbayya Hegde oversees operations."
    matches = detector.detect_in_segment("seg_1", text)
    assert len(matches) >= 1
    assert any("Kushal Subbayya Hegde" in m.text for m in matches)


def test_generic_terms_rejected_as_person(detector):
    bad_phrases = [
        "The Offer",
        "Offer Price",
        "Equity Shares",
        "Capital Structure",
        "Financial Statements",
        "Independent Director",
        "Companies Act",
        "Return on Capital Employed",
        "Revenue from Operations",
    ]
    for phrase in bad_phrases:
        matches = detector.detect_in_segment("seg_test", phrase)
        assert len(matches) == 0, f"'{phrase}' must NEVER be detected as PERSON."
