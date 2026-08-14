"""
test_dob_context.py
-------------------
Tests asserting that ordinary document dates are NEVER classified as DOBs,
and that DOB detection strictly requires explicit birth context.
"""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from detectors import DOBDetector


@pytest.fixture
def detector():
    return DOBDetector()


def test_prospectus_header_date_never_detected(detector):
    text = "Dated December 10, 2025"
    matches = detector.detect_in_segment("seg_1", text)
    assert len(matches) == 0, "Ordinary header date 'Dated December 10, 2025' must NEVER be detected as DOB!"


def test_ordinary_calendar_dates_ignored(detector):
    sample_dates = [
        "December 31, 2024",
        "March 31, 2023",
        "As of June 30, 2025",
        "Registered on 15/08/1979",
        "Bid Opening Date: January 15, 2026",
    ]
    for d in sample_dates:
        matches = detector.detect_in_segment("seg_date", d)
        assert len(matches) == 0, f"Ordinary date '{d}' must not be detected as DOB."


def test_explicit_dob_with_context_detected(detector):
    valid_dobs = [
        ("Date of Birth: 15/08/1985", "15/08/1985"),
        ("DOB: January 15, 1980", "January 15, 1980"),
        ("Born on: 12-04-1975", "12-04-1975"),
        ("D.O.B.: 01/01/1990", "01/01/1990"),
    ]
    for text, expected_span in valid_dobs:
        matches = detector.detect_in_segment("seg_dob", text)
        assert len(matches) == 1, f"Failed to detect DOB in '{text}'"
        assert matches[0].text == expected_span
