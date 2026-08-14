"""
test_address_context.py
-----------------------
Tests asserting that physical addresses are only detected as complete blocks from context labels,
and that standalone geographic words (cities, states, countries) are NEVER redacted.
"""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from detectors import AddressDetector


@pytest.fixture
def detector():
    return AddressDetector()


def test_registered_office_address_block(detector):
    text = (
        "Registered Office: 11/3, 11/4 and 11/5, Village Birdewadi, "
        "Chakan Taluka - Khed, Pune – 410 501, Maharashtra, India"
    )
    matches = detector.detect_in_segment("seg_1", text)
    assert len(matches) == 1
    assert "11/3, 11/4 and 11/5" in matches[0].text
    assert "India" in matches[0].text


def test_standalone_geographic_words_never_detected(detector):
    geo_words = [
        "Pune",
        "Mumbai",
        "Maharashtra",
        "India",
        "New Delhi",
        "Bengaluru",
        "Gujarat",
    ]
    for geo in geo_words:
        matches = detector.detect_in_segment("seg_geo", geo)
        assert len(matches) == 0, f"Standalone geographic word '{geo}' must NEVER be detected as ADDRESS!"
