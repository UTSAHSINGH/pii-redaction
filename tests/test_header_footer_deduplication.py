"""
test_header_footer_deduplication.py
-----------------------------------
Tests asserting that shared section headers and footers are processed once per unique XML part.
"""

import sys
from pathlib import Path
import pytest
from docx import Document

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from document_processor import extract_document_segments


def test_shared_header_footer_deduplication():
    doc = Document()
    s1 = doc.sections[0]
    s1.header.paragraphs[0].text = "Header Text: Red Herring Prospectus"

    # Add section 2 with linked header (same underlying XML part)
    s2 = doc.add_section()

    segments = extract_document_segments(doc)
    header_segs = [s for s in segments if "Header Text" in s.text]
    assert len(header_segs) == 1, "Shared XML headers must be processed exactly once!"
