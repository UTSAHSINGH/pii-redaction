"""
test_address_general.py
-----------------------
Tests for general-purpose multi-signal ADDRESS detection across international and domestic formats.
"""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from detectors.address import AddressDetector
from detectors.base import DetectionContext
from models import DocumentSegment


@pytest.fixture
def detector():
    return AddressDetector()


@pytest.fixture
def context():
    return DetectionContext()


def test_us_structural_address(detector, context):
    seg = DocumentSegment(
        segment_id="s1",
        text="Please send the contract to 1600 Pennsylvania Avenue NW, Washington DC 20500, USA."
    )
    matches = detector.detect(seg, context)
    assert len(matches) == 1
    assert "1600 Pennsylvania Avenue NW" in matches[0].text
    assert "20500" in matches[0].text


def test_uk_structural_address(detector, context):
    seg = DocumentSegment(
        segment_id="s2",
        text="Headquarters at 221 Baker Street, London NW1 6XE, United Kingdom."
    )
    matches = detector.detect(seg, context)
    assert len(matches) == 1
    assert "221 Baker Street" in matches[0].text


def test_indian_registered_office_address(detector, context):
    seg = DocumentSegment(
        segment_id="s3",
        text="Registered Office: Plot No. 45, Sector 18, Chakan Industrial Area, Pune 411001, Maharashtra, India."
    )
    matches = detector.detect(seg, context)
    assert len(matches) == 1
    assert "Plot No. 45" in matches[0].text
    assert "India" in matches[0].text


def test_standalone_geographic_words_never_redacted(detector, context):
    geo_samples = [
        "London is the capital of England.",
        "We are expanding our presence in Mumbai and Bengaluru.",
        "The conference will be held in California, USA.",
        "Shipments across India and Europe are on schedule.",
    ]
    for sample in geo_samples:
        seg = DocumentSegment(segment_id="geo", text=sample)
        matches = detector.detect(seg, context)
        assert len(matches) == 0, f"Standalone city/country name in '{sample}' must NEVER be detected as ADDRESS!"
