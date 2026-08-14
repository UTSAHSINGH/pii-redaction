"""
test_redaction_strategies.py
----------------------------
Tests for all 4 PII Shield redaction strategies:
1. SYNTHETIC (Realistic Faker fake data)
2. MASK (Sensitive character masking)
3. TOKEN (Sequential numbered tokens)
4. CATEGORY_LABEL (Category tags)
"""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from models import PIIMatch, RedactionStrategy
from replacement_generator import get_replacement, reset_generator_state


@pytest.fixture(autouse=True)
def clean_state():
    reset_generator_state()


def test_synthetic_strategy_deterministic():
    m = PIIMatch(
        match_id="1", segment_id="s", entity_type="PERSON", start=0, end=10,
        text="John Smith", confidence=0.98
    )
    rep1 = get_replacement(m, RedactionStrategy.SYNTHETIC, seed=42)
    rep2 = get_replacement(m, RedactionStrategy.SYNTHETIC, seed=42)
    assert rep1 == rep2
    assert rep1 != "John Smith"
    assert len(rep1.split()) == 2


def test_mask_strategy_email():
    m = PIIMatch(
        match_id="2", segment_id="s", entity_type="EMAIL", start=0, end=20,
        text="alex.morgan@test.com", confidence=0.99
    )
    masked = get_replacement(m, RedactionStrategy.MASK)
    assert masked.startswith("a***@test.com")


def test_mask_strategy_phone():
    m = PIIMatch(
        match_id="3", segment_id="s", entity_type="PHONE", start=0, end=17,
        text="+91 98765 43210", confidence=0.98
    )
    masked = get_replacement(m, RedactionStrategy.MASK)
    assert masked == "+91 XXXXX XXXXX"


def test_token_strategy():
    m1 = PIIMatch(
        match_id="4", segment_id="s", entity_type="PERSON", start=0, end=8,
        text="John Doe", confidence=0.98
    )
    m2 = PIIMatch(
        match_id="5", segment_id="s", entity_type="PERSON", start=0, end=10,
        text="Jane Smith", confidence=0.98
    )
    t1 = get_replacement(m1, RedactionStrategy.TOKEN)
    t2 = get_replacement(m2, RedactionStrategy.TOKEN)
    assert t1 == "<PERSON_001>"
    assert t2 == "<PERSON_002>"


def test_category_label_strategy():
    m = PIIMatch(
        match_id="6", segment_id="s", entity_type="ADDRESS", start=0, end=20,
        text="1600 Pennsylvania Ave", confidence=0.95
    )
    label = get_replacement(m, RedactionStrategy.CATEGORY_LABEL)
    assert label == "[REDACTED ADDRESS]"
