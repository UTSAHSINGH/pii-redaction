"""
pii_redactor.py
---------------
Main Orchestration Pipeline for PII Redaction.

Pipeline Architecture:
    ORIGINAL DOCX
        │
        ▼
    IMMUTABLE TEXT SNAPSHOT
        │
        ▼
    PII DETECTION (Context-Gated Detectors)
        │
        ▼
    APPROVED MATCHES ONLY (Strict Overlap Resolution & Span Validation)
        │
        ▼
    FROZEN REPLACEMENT PLAN (Deterministic SHA-256 Seeded Fake Values)
        │
        ▼
    EXACT SPAN PATCH (Right-to-Left Run-Level In-Place Mutation)
        │
        ▼
    OUTPUT DOCX
        │
        ▼
    INDEPENDENT INTEGRITY VERIFIER (Cryptographic Assertion of Invariant)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from docx import Document

from detectors import DETECTORS, ENABLE_ENTITY_PROPAGATION
from document_processor import (
    DocumentSegment,
    apply_replacements_to_segment,
    extract_document_segments,
    get_document_stats,
    patch_hyperlink_targets,
    reconstruct_expected_text,
)
from integrity_verifier import verify_document_integrity
from replacement_generator import get_replacement
from utils import PIIMatch, hash_text, resolve_overlaps, save_json, setup_logger, validate_match_span

log = setup_logger("pii_redactor")


# ---------------------------------------------------------------------------
# PIIRedactor Class
# ---------------------------------------------------------------------------

class PIIRedactor:
    """
    Production PII Redactor implementing exact-span detection, deterministic
    replacement, and character-level non-PII preservation.
    """

    def __init__(
        self,
        input_path: str | Path,
        output_path: str | Path,
        log_path: Optional[str | Path] = None,
    ) -> None:
        self.input_path = Path(input_path)
        self.output_path = Path(output_path)
        self.log_path = (
            Path(log_path)
            if log_path
            else self.output_path.parent / "PII_REDACTION_LOG.json"
        )

    # ------------------------------------------------------------------
    # Main Pipeline Execution
    # ------------------------------------------------------------------
    def run(self) -> Dict:
        """Execute the complete redaction pipeline and return a summary dict."""
        log.info("=" * 70)
        log.info("PII Redaction Pipeline Starting")
        log.info("Input:  %s", self.input_path)
        log.info("Output: %s", self.output_path)
        log.info("=" * 70)

        # 1. Load document and extract immutable segments
        doc = self._load_document()
        doc_stats = get_document_stats(doc)
        segments = extract_document_segments(doc)
        log.info(
            "Document loaded: %d paragraphs, %d tables, %d unique segments.",
            doc_stats["paragraphs"], doc_stats["tables"], len(segments)
        )

        # 2. Run detectors on immutable original segment text
        raw_matches = self._detect_all_segments(segments)
        log.info("Raw validated matches detected: %d", len(raw_matches))

        # 3. Resolve overlaps per segment (Approved Matches Only)
        resolved_matches = resolve_overlaps(raw_matches)
        log.info("Accepted non-overlapping matches: %d", len(resolved_matches))

        # 4. Generate frozen deterministic replacement plan
        for match in resolved_matches:
            match.replacement = get_replacement(match)

        # 5. Group matches by segment_id for structured application
        matches_by_seg: Dict[str, List[PIIMatch]] = {}
        for match in resolved_matches:
            matches_by_seg.setdefault(match.segment_id, []).append(match)

        # 6. Apply replacements in-place to DOCX runs (Right-to-Left)
        for seg in segments:
            seg_matches = matches_by_seg.get(seg.segment_id, [])
            if seg_matches:
                apply_replacements_to_segment(seg, seg_matches)

        # 7. Patch hyperlink relationship targets (mailto:)
        patched_hyperlinks = patch_hyperlink_targets(doc, resolved_matches)
        log.info("Patched %d hyperlink relationship targets.", patched_hyperlinks)

        # 8. Save output DOCX (with fallback if primary path is locked)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            doc.save(str(self.output_path))
            log.info("Redacted document saved → %s", self.output_path)
        except PermissionError:
            fallback = self.output_path.parent / (self.output_path.stem + "_redacted.docx")
            log.warning("Primary output %s is locked by an external process. Saving to: %s", self.output_path, fallback)
            self.output_path = fallback
            doc.save(str(self.output_path))
            log.info("Redacted document saved → %s", self.output_path)

        # 9. Write audit log (privacy-safe, no raw PII in public fields)
        self._write_audit_log(resolved_matches)

        # 10. Independent Integrity Verification Gate
        integrity_report = verify_document_integrity(
            original_docx_path=self.input_path,
            redacted_docx_path=self.output_path,
            redaction_log_path=self.log_path,
            report_output_path=self.output_path.parent.parent / "evaluation" / "document_integrity_report.json",
            diff_output_path=self.output_path.parent.parent / "evaluation" / "semantic_diff.json",
        )

        if integrity_report["status"] != "PASS":
            raise RuntimeError(
                f"Document Integrity Gate FAILED: {integrity_report['segments_with_unexpected_changes']} unexpected segments, "
                f"{integrity_report['unauthorized_changed_characters']} unauthorized changed characters."
            )

        log.info("Document Integrity Gate PASSED: 100%% non-PII characters preserved.")

        # 11. Build and return summary dict
        summary = self._build_summary(resolved_matches, doc_stats, len(segments))
        summary["integrity_report"] = integrity_report
        return summary

    # ------------------------------------------------------------------
    # Step 1: Load Document
    # ------------------------------------------------------------------
    def _load_document(self) -> Document:
        if not self.input_path.exists():
            raise FileNotFoundError(f"Input file not found: {self.input_path}")
        return Document(str(self.input_path))

    # ------------------------------------------------------------------
    # Step 2: Detect in All Segments with Strict Span Validation
    # ------------------------------------------------------------------
    def _detect_all_segments(self, segments: List[DocumentSegment]) -> List[PIIMatch]:
        validated_matches: List[PIIMatch] = []

        for seg in segments:
            if not seg.text.strip():
                continue

            for detector in DETECTORS:
                try:
                    seg_matches = detector.detect_in_segment(seg.segment_id, seg.text)
                    for m in seg_matches:
                        if validate_match_span(m, seg.text):
                            validated_matches.append(m)
                        else:
                            log.warning("Rejected invalid span [%d:%d] in '%s'", m.start, m.end, seg.segment_id)
                except Exception as exc:
                    log.error("Detector %s error on segment %s: %s", detector.__class__.__name__, seg.segment_id, exc)

        return validated_matches

    # ------------------------------------------------------------------
    # Step 9: Write Structured Audit Log
    # ------------------------------------------------------------------
    def _write_audit_log(self, matches: List[PIIMatch]) -> None:
        log_entries = []
        for m in matches:
            log_entries.append({
                "segment_id": m.segment_id,
                "entity_type": m.entity_type,
                "text": m.text,
                "start": m.start,
                "end": m.end,
                "replacement": m.replacement,
                "confidence": round(m.confidence, 4),
                "source": m.source,
                "original_hash": hash_text(m.text),
            })
        save_json(log_entries, self.log_path)

    # ------------------------------------------------------------------
    # Step 11: Summary Builder
    # ------------------------------------------------------------------
    def _build_summary(
        self,
        matches: List[PIIMatch],
        doc_stats: Dict,
        unique_segments: int,
    ) -> Dict:
        by_type: Dict[str, int] = {}
        for m in matches:
            by_type[m.entity_type] = by_type.get(m.entity_type, 0) + 1

        return {
            "input": str(self.input_path),
            "output": str(self.output_path),
            "total_redactions": len(matches),
            "by_entity_type": by_type,
            "document_stats": {
                **doc_stats,
                "unique_segments": unique_segments,
            },
        }
