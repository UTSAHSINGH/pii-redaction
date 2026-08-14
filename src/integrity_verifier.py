"""
integrity_verifier.py
---------------------
Independent, Cryptographic-Style Output Document Integrity Verifier.

This verifier has NO dependency on the redaction replacement engine.
It verifies the Absolute Invariant:
    For every document segment:
        expected_output = apply_only_approved_spans(original_text, approved_matches)
        actual_output   = text_extracted_from_written_docx
        Require: actual_output == expected_output

If even one unexpected character changes anywhere in the document:
    status = FAIL
"""

from __future__ import annotations

import difflib
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from docx import Document

from document_processor import DocumentSegment, extract_document_segments
from utils import PIIMatch, save_json, setup_logger

log = setup_logger("integrity_verifier")


def apply_only_approved_spans(
    original_text: str,
    approved_matches: List[Dict[str, Any]],
) -> str:
    """
    Reconstruct expected text by applying ONLY approved redactions right-to-left.
    Operates strictly on character slices of the immutable original text.
    """
    if not approved_matches:
        return original_text

    # Sort strictly from right to left (descending start offset)
    sorted_matches = sorted(approved_matches, key=lambda m: m["start"], reverse=True)

    result = list(original_text)
    for m in sorted_matches:
        start = m["start"]
        end = m["end"]
        replacement = m.get("replacement", "")

        # Verify span in original text
        expected_orig = m.get("text", "")
        actual_orig = original_text[start:end]
        if expected_orig and actual_orig != expected_orig:
            log.error(
                "Verifier span mismatch: expected '%s', found '%s' at [%d:%d]",
                expected_orig, actual_orig, start, end
            )

        result[start:end] = list(replacement)

    return "".join(result)


def verify_document_integrity(
    original_docx_path: str | Path,
    redacted_docx_path: str | Path,
    redaction_log_path: str | Path,
    report_output_path: Optional[str | Path] = None,
    diff_output_path: Optional[str | Path] = None,
) -> Dict[str, Any]:
    """
    Independently inspects and compares the original DOCX against the redacted DOCX
    and the approved redaction log.

    Returns integrity metrics and generates semantic diffs.
    """
    orig_path = Path(original_docx_path)
    red_path = Path(redacted_docx_path)
    log_path = Path(redaction_log_path)

    if not orig_path.exists():
        raise FileNotFoundError(f"Original DOCX not found: {orig_path}")
    if not red_path.exists():
        raise FileNotFoundError(f"Redacted DOCX not found: {red_path}")
    if not log_path.exists():
        raise FileNotFoundError(f"Redaction log not found: {log_path}")

    # 1. Load DOCX documents
    orig_doc = Document(str(orig_path))
    red_doc = Document(str(red_path))

    # 2. Extract document segments independently
    orig_segments = extract_document_segments(orig_doc)
    red_segments = extract_document_segments(red_doc)

    orig_seg_map = {s.segment_id: s for s in orig_segments}
    red_seg_map = {s.segment_id: s for s in red_segments}

    # 3. Load approved redactions from log
    with open(log_path, encoding="utf-8") as f:
        approved_log: List[Dict[str, Any]] = json.load(f)

    # Group approved redactions by segment_id
    approved_by_seg: Dict[str, List[Dict[str, Any]]] = {}
    for item in approved_log:
        seg_id = item["segment_id"]
        approved_by_seg.setdefault(seg_id, []).append(item)

    # 4. Compare every segment
    segments_checked = len(orig_segments)
    segments_with_expected_redactions = 0
    segments_with_unexpected_changes = 0
    unauthorized_changed_characters = 0
    total_original_characters = sum(len(s.text) for s in orig_segments)
    total_approved_spans = len(approved_log)

    semantic_diffs: List[Dict[str, Any]] = []
    failed_segments: List[Dict[str, Any]] = []

    for orig_seg in orig_segments:
        seg_id = orig_seg.segment_id
        red_seg = red_seg_map.get(seg_id)

        if red_seg is None:
            segments_with_unexpected_changes += 1
            unauthorized_changed_characters += len(orig_seg.text)
            failed_segments.append({
                "segment_id": seg_id,
                "error": "Segment missing from redacted document",
                "original_text": orig_seg.text,
            })
            continue

        seg_approved = approved_by_seg.get(seg_id, [])
        if seg_approved:
            segments_with_expected_redactions += 1

        # Reconstruct expected output strictly from approved spans
        expected_text = apply_only_approved_spans(orig_seg.text, seg_approved)
        actual_text = red_seg.text

        # Record approved semantic changes
        for app in seg_approved:
            semantic_diffs.append({
                "segment_id": seg_id,
                "start": app["start"],
                "end": app["end"],
                "entity_type": app["entity_type"],
                "original_text": app.get("text", orig_seg.text[app["start"]:app["end"]]),
                "replacement": app["replacement"],
                "approved": True,
            })

        # Check invariant: actual_output == expected_output
        if actual_text != expected_text:
            segments_with_unexpected_changes += 1

            # Count unauthorized changed characters using diff
            diff = list(difflib.ndiff(expected_text, actual_text))
            diff_changes = sum(1 for d in diff if d.startswith("+ ") or d.startswith("- "))
            unauthorized_changed_characters += diff_changes

            # Record unauthorized change in semantic diff
            semantic_diffs.append({
                "segment_id": seg_id,
                "error": "Unauthorized mutation detected",
                "expected_text": expected_text,
                "actual_text": actual_text,
                "approved": False,
            })

            failed_segments.append({
                "segment_id": seg_id,
                "original_text": orig_seg.text,
                "expected_text": expected_text,
                "actual_text": actual_text,
                "diff_sample": "".join(diff[:100]),
            })

    unauthorized_change_rate = (
        unauthorized_changed_characters / total_original_characters
        if total_original_characters > 0 else 0.0
    )
    non_pii_preservation_rate = max(0.0, 1.0 - unauthorized_change_rate)
    is_pass = (
        segments_with_unexpected_changes == 0
        and unauthorized_changed_characters == 0
    )

    report: Dict[str, Any] = {
        "segments_checked": segments_checked,
        "segments_with_expected_redactions": segments_with_expected_redactions,
        "segments_with_unexpected_changes": segments_with_unexpected_changes,
        "unauthorized_changed_characters": unauthorized_changed_characters,
        "total_original_characters": total_original_characters,
        "unauthorized_change_rate": unauthorized_change_rate,
        "non_pii_preservation_rate": non_pii_preservation_rate,
        "total_approved_spans": total_approved_spans,
        "status": "PASS" if is_pass else "FAIL",
        "failed_segments_sample": failed_segments[:10],
    }

    if report_output_path:
        save_json(report, report_output_path)
    if diff_output_path:
        save_json(semantic_diffs, diff_output_path)

    log.info(
        "Document Integrity Verification: %s (Segments Checked: %d, Unexpected Changes: %d, Unauthorized Chars: %d)",
        report["status"], segments_checked, segments_with_unexpected_changes, unauthorized_changed_characters
    )

    return report
