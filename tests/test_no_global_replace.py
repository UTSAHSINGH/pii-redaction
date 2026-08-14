"""
test_no_global_replace.py
-------------------------
Tests verifying that no global substring replace or global entity propagation occurs.
"""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from detectors import ENABLE_ENTITY_PROPAGATION, PersonDetector
from pii_redactor import PIIRedactor


def test_propagation_flag_is_disabled():
    assert not ENABLE_ENTITY_PROPAGATION, "ENABLE_ENTITY_PROPAGATION must be False."


def test_no_uncontextual_propagation():
    detector = PersonDetector()
    # "Sarthak Malvadkar" with role context should be detected
    seg1 = "Company Secretary: Sarthak Malvadkar"
    m1 = detector.detect_in_segment("seg_1", seg1)
    assert len(m1) > 0
    assert m1[0].text == "Sarthak Malvadkar"

    # Generic uncontextual mention of generic words should NOT match
    seg2 = "The Offer consists of Equity Shares and Capital Structure."
    m2 = detector.detect_in_segment("seg_2", seg2)
    assert len(m2) == 0
