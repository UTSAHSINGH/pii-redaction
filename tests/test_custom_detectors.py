"""
test_custom_detectors.py
------------------------
Tests for user-defined custom PII regex detectors.
"""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from detectors.custom import CustomIdentifierDetector
from detectors.base import DetectionContext
from models import CustomDetectorConfig, DocumentSegment


def test_custom_employee_id_detector():
    config = CustomDetectorConfig(
        entity_name="EMPLOYEE_ID",
        pattern=r"\bEMP-\d{4}-[A-Z]{2}\b",
        confidence=0.92,
    )
    detector = CustomIdentifierDetector(config)
    context = DetectionContext()

    seg = DocumentSegment(
        segment_id="s1",
        text="Employee assigned: EMP-9821-NY for project onboarding."
    )
    matches = detector.detect(seg, context)
    assert len(matches) == 1
    assert matches[0].entity_type == "EMPLOYEE_ID"
    assert matches[0].text == "EMP-9821-NY"
    assert matches[0].confidence == 0.92


def test_custom_project_code_detector():
    config = CustomDetectorConfig(
        entity_name="PROJECT_CODE",
        pattern=r"\bPRJ-[0-9]{6}\b",
        confidence=0.95,
    )
    detector = CustomIdentifierDetector(config)
    context = DetectionContext()

    seg = DocumentSegment(
        segment_id="s2",
        text="Deliverables under PRJ-102938 are marked confidential."
    )
    matches = detector.detect(seg, context)
    assert len(matches) == 1
    assert matches[0].text == "PRJ-102938"
