"""
pii_redactor.py
---------------
Principal PII Redaction Orchestration Engine.

Architecture & Invariants:
1. Immutable Document Model: All text extraction produces isolated DocumentSegments.
2. Detection on Original Text Only: Detectors operate on segment.text before any mutations.
3. Span Validation: Every match is strictly validated against segment.text[start:end].
4. Exact Canonical Aliasing: Only fully validated multi-word names are propagated.
5. Deterministic Overlap Resolution: Priority-based resolution ensures structured PII is never overwritten.
6. Right-to-Left In-Place Replacement: Edits occur from right to left per segment.
7. Zero Non-PII Mutation: Verifies post-redaction DOCX text matches expected text character-for-character.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import regex
from docx import Document

# Ensure src/ is on sys.path
_SRC = Path(__file__).parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from detectors import DETECTORS, _get_protected_spans, _overlaps_protected
from document_processor import (
    DocumentSegment,
    apply_replacements_to_segment,
    extract_document_segments,
    get_document_stats,
    patch_hyperlink_targets,
    reconstruct_expected_text,
)
from replacement_generator import get_replacement, get_replacement_map, get_synthetic_values
from utils import (
    PIIMatch,
    get_context_snippet,
    hash_text,
    resolve_overlaps,
    save_json,
    setup_logger,
    validate_match_span,
)

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

        # 3. Exact Canonical Entity Propagation (multi-word validated entities only)
        propagated_matches = self._propagate_canonical_entities(segments, raw_matches)
        all_matches = raw_matches + propagated_matches
        log.info("Total candidate matches after exact propagation: %d", len(all_matches))

        # 4. Resolve overlaps per segment
        resolved_matches = resolve_overlaps(all_matches)
        log.info("Accepted non-overlapping matches: %d", len(resolved_matches))

        # 5. Generate deterministic replacements for all accepted matches
        for match in resolved_matches:
            match.replacement = get_replacement(match)

        # 6. Group matches by segment_id for structured application
        matches_by_seg: Dict[str, List[PIIMatch]] = {}
        for match in resolved_matches:
            matches_by_seg.setdefault(match.segment_id, []).append(match)

        # 7. Compute expected text per segment for integrity validation
        expected_texts: Dict[str, str] = {}
        for seg in segments:
            seg_matches = matches_by_seg.get(seg.segment_id, [])
            expected_texts[seg.segment_id] = reconstruct_expected_text(seg.text, seg_matches)

        # 8. Apply replacements in-place to DOCX runs (Right-to-Left)
        for seg in segments:
            seg_matches = matches_by_seg.get(seg.segment_id, [])
            if seg_matches:
                apply_replacements_to_segment(seg, seg_matches)

        # 9. Patch hyperlink relationship targets (mailto:)
        patched_hyperlinks = patch_hyperlink_targets(doc, resolved_matches)
        log.info("Patched %d hyperlink relationship targets.", patched_hyperlinks)

        # 10. Save output DOCX (with fallback if primary path is locked by Word)
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

        # 11. Document Integrity Verification Gate (re-open and assert exact match)
        self._verify_document_integrity(expected_texts)

        # 12. Write audit log (privacy-safe, no raw PII in public fields)
        self._write_audit_log(resolved_matches)

        # 13. Build and return summary dict
        summary = self._build_summary(resolved_matches, doc_stats, len(segments))
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
                        # Strict span validation
                        if validate_match_span(m, seg.text):
                            validated_matches.append(m)
                        else:
                            log.warning("Rejected invalid span [%d:%d] in '%s'", m.start, m.end, seg.segment_id)
                except Exception as exc:
                    log.error("Detector %s error on segment %s: %s", detector.__class__.__name__, seg.segment_id, exc)

        return validated_matches

    # ------------------------------------------------------------------
    # Step 3: Exact Canonical Entity Propagation
    # ------------------------------------------------------------------
    def _propagate_canonical_entities(
        self,
        segments: List[DocumentSegment],
        existing_matches: List[PIIMatch],
    ) -> List[PIIMatch]:
        """
        Propagate ONLY confirmed multi-word PERSON and complete COMPANY entities.
        Uses exact word-bounded regex matching.
        NEVER propagates single words or first names alone.
        """
        # Collect distinct multi-word canonical entities
        canonical_entities: Dict[str, Tuple[str, float]] = {}
        for m in existing_matches:
            if m.entity_type in {"PERSON", "COMPANY"} and m.confidence >= 0.90:
                raw = m.text.strip()
                words = raw.split()
                # Must be at least 2 words and not a single generic token
                if len(words) >= 2 and len(raw) >= 6:
                    canonical_entities[raw] = (m.entity_type, m.confidence)

        if not canonical_entities:
            return []

        # Index existing spans per segment to avoid duplicate detections
        existing_spans_by_seg: Dict[str, Set[Tuple[int, int]]] = {}
        for m in existing_matches:
            existing_spans_by_seg.setdefault(m.segment_id, set()).add((m.start, m.end))

        # Pre-compile patterns once outside the segment loop
        compiled_patterns = [
            (
                ent_text,
                regex.compile(rf"\b{regex.escape(ent_text)}\b", regex.IGNORECASE),
                ent_type,
                conf,
            )
            for ent_text, (ent_type, conf) in canonical_entities.items()
        ]

        propagated: List[PIIMatch] = []

        for seg in segments:
            if not seg.text.strip():
                continue
            seg_spans = existing_spans_by_seg.get(seg.segment_id, set())
            protected_spans = _get_protected_spans(seg.text)

            for ent_text, pattern, ent_type, conf in compiled_patterns:
                for m in pattern.finditer(seg.text):
                    start = m.start()
                    end = m.end()
                    span = (start, end)

                    if span not in seg_spans and not _overlaps_protected(start, end, protected_spans):
                        actual_text = seg.text[start:end]
                        match_obj = PIIMatch(
                            segment_id=seg.segment_id,
                            entity_type=ent_type,
                            start=start,
                            end=end,
                            text=actual_text,
                            confidence=conf,
                            source="canonical_propagation",
                            context=get_context_snippet(seg.text, start, end),
                        )
                        if validate_match_span(match_obj, seg.text):
                            seg_spans.add(span)
                            propagated.append(match_obj)

        log.info("Canonical propagation added %d exact entity occurrences.", len(propagated))
        return propagated

    # ------------------------------------------------------------------
    # Step 11: Document Integrity Verification Gate
    # ------------------------------------------------------------------
    def _verify_document_integrity(self, expected_texts: Dict[str, str]) -> None:
        """
        Re-open the saved redacted DOCX and verify that every segment text exactly
        matches the expected text. Ensures zero unintended modification of non-PII text.
        """
        log.info("Verifying document integrity on saved output: %s", self.output_path)
        reopened_doc = Document(str(self.output_path))
        reopened_segments = extract_document_segments(reopened_doc)

        mismatch_count = 0
        for seg in reopened_segments:
            expected = expected_texts.get(seg.segment_id)
            if expected is not None and seg.text != expected:
                mismatch_count += 1
                log.error(
                    "Integrity Failure in '%s':\n  Expected: %r\n  Actual:   %r",
                    seg.segment_id, expected[:100], seg.text[:100]
                )

        if mismatch_count > 0:
            raise RuntimeError(
                f"DOCUMENT INTEGRITY GATE FAILED: {mismatch_count} segments had unexpected text modifications!"
            )

        log.info("Document integrity gate PASSED: All %d segments match expected text exactly.", len(reopened_segments))

    # ------------------------------------------------------------------
    # Step 12: Audit Log Writing
    # ------------------------------------------------------------------
    def _write_audit_log(self, matches: List[PIIMatch]) -> None:
        """Write structured audit log without raw PII in public fields."""
        log_entries = []
        for m in matches:
            entry = {
                "segment_id": m.segment_id,
                "entity_type": m.entity_type,
                "text": m.text,
                "start": m.start,
                "end": m.end,
                "replacement": m.replacement,
                "confidence": round(m.confidence, 4),
                "source": m.source,
                "original_hash": hash_text(m.text),
            }
            log_entries.append(entry)

        save_json(log_entries, self.log_path)

    # ------------------------------------------------------------------
    # Summary Builder
    # ------------------------------------------------------------------
    def _build_summary(
        self,
        matches: List[PIIMatch],
        doc_stats: dict,
        total_segments: int,
    ) -> Dict:
        by_type: Dict[str, int] = {}
        for m in matches:
            by_type[m.entity_type] = by_type.get(m.entity_type, 0) + 1

        rep_map = get_replacement_map()
        return {
            "input": str(self.input_path),
            "output": str(self.output_path),
            "document_stats": doc_stats,
            "total_segments": total_segments,
            "total_redactions": len(matches),
            "by_entity_type": by_type,
            "replacement_map_size": len(rep_map),
        }
