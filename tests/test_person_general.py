"""
test_person_general.py
----------------------
Tests for multi-stage PERSON detection across diverse document domains
without hardcoded names.
"""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from detectors.person import PersonDetector
from detectors.base import DetectionContext
from models import ConfidenceTier, DocumentSegment


@pytest.fixture
def detector():
    return PersonDetector()


@pytest.fixture
def context():
    return DetectionContext()


def test_salutation_name_detection(detector, context):
    seg = DocumentSegment(
        segment_id="s1",
        text="Application submitted by Dr. Sarah Wilson and reviewed by Mr. Jonathan Davis."
    )
    matches = detector.detect(seg, context)
    assert len(matches) == 2
    names = [m.text for m in matches]
    assert any("Sarah Wilson" in n for n in names)
    assert any("Jonathan Davis" in n for n in names)
    assert all(m.confidence_tier == ConfidenceTier.HIGH for m in matches)


def test_role_context_name_detection(detector, context):
    seg = DocumentSegment(
        segment_id="s2",
        text="Contact Person: David Miller (VP of Operations); Managing Director: Alex Morgan."
    )
    matches = detector.detect(seg, context)
    assert len(matches) >= 2
    names = [m.text for m in matches]
    assert "David Miller" in names
    assert "Alex Morgan" in names


def test_negative_domain_terms_never_detected_as_person(detector, context):
    bad_terms = [
        "Executive Summary",
        "Financial Statements",
        "Capital Structure",
        "Offer Price",
        "Terms and Conditions",
        "Table of Contents",
        "Board of Directors",
        "Independent Director",
        "Revenue from Operations",
    ]
    for term in bad_terms:
        seg = DocumentSegment(segment_id="bad", text=term)
        matches = detector.detect(seg, context)
        assert len(matches) == 0, f"Domain term '{term}' must NEVER be detected as PERSON!"
