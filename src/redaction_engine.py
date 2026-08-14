"""
redaction_engine.py
-------------------
Core Pipeline Engine for PII Shield.
Orchestrates multi-format extraction, detection, overlap resolution, review actions,
exact-span application, independent integrity verification, and audit report generation.
"""

from __future__ import annotations

from datetime import datetime
import json
import logging
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple

from adapters.base import DocumentAdapter, NormalizedDocument
from adapters.registry import get_adapter_for_file
from detectors.registry import DEFAULT_REGISTRY, DetectorRegistry
from integrity_verifier import verify_document_integrity
from models import (
    ConfidenceTier,
    DetectionConfig,
    DocumentAuditSummary,
    DocumentSegment,
    IntegrityReport,
    PIIMatch,
    RedactionStrategy,
    ReviewActionType,
    ReviewSubmission,
)
from replacement_generator import get_replacement, reset_generator_state
from utils import hash_text, save_json, setup_logger

log = setup_logger("pii_shield")


class RedactionEngine:
    """Enterprise-grade document PII detection and redaction engine."""

    def __init__(self, registry: Optional[DetectorRegistry] = None) -> None:
        self.registry = registry or DEFAULT_REGISTRY

    def scan_document(
        self,
        file_source: str | Path | bytes,
        filename: str,
        config: Optional[DetectionConfig] = None,
    ) -> Tuple[NormalizedDocument, List[PIIMatch]]:
        """Extract segments and detect candidate PII matches without applying changes."""
        config = config or DetectionConfig()
        adapter: DocumentAdapter = get_adapter_for_file(filename)
        doc: NormalizedDocument = adapter.extract(file_source, filename)

        raw_matches = self.registry.scan_segments(doc.segments, config)
        resolved_matches = self.resolve_overlaps(raw_matches)

        # Precompute candidate replacements
        for m in resolved_matches:
            m.replacement = get_replacement(m, config.redaction_strategy, config.seed)

        return doc, resolved_matches

    def apply_review_and_redact(
        self,
        doc: NormalizedDocument,
        matches: List[PIIMatch],
        reviews: Optional[List[ReviewSubmission]] = None,
        config: Optional[DetectionConfig] = None,
    ) -> Tuple[bytes, List[PIIMatch]]:
        """Apply human-in-the-loop review actions and render redacted document bytes."""
        config = config or DetectionConfig()
        adapter: DocumentAdapter = get_adapter_for_file(doc.filename)

        # 1. Apply user review actions if provided
        match_dict = {m.match_id: m for m in matches}
        if reviews:
            for r in reviews:
                if r.match_id in match_dict:
                    target_match = match_dict[r.match_id]
                    if r.action == ReviewActionType.APPROVE:
                        target_match.approved = True
                    elif r.action == ReviewActionType.REJECT:
                        target_match.approved = False
                    elif r.action == ReviewActionType.EDIT:
                        if r.edited_text:
                            target_match.text = r.edited_text
                        if r.replacement_override:
                            target_match.replacement = r.replacement_override
                        target_match.user_edited = True
                        target_match.approved = True
                    elif r.action == ReviewActionType.CHANGE_TYPE:
                        if r.edited_entity_type:
                            target_match.entity_type = r.edited_entity_type
                            target_match.replacement = get_replacement(
                                target_match, config.redaction_strategy, config.seed
                            )
                        target_match.user_edited = True
                        target_match.approved = True

        # 2. Filter strictly to approved matches
        approved_matches = [m for m in matches if m.approved]

        # 3. Ensure replacements exist for all approved matches
        for m in approved_matches:
            if not m.replacement:
                m.replacement = get_replacement(m, config.redaction_strategy, config.seed)

        # 4. Render redacted bytes via format-specific adapter
        redacted_bytes = adapter.apply_redactions(doc, approved_matches)
        return redacted_bytes, approved_matches

    def resolve_overlaps(self, matches: List[PIIMatch]) -> List[PIIMatch]:
        """Resolve overlapping PII candidate spans within each segment by confidence and length."""
        by_segment: Dict[str, List[PIIMatch]] = {}
        for m in matches:
            by_segment.setdefault(m.segment_id, []).append(m)

        resolved: List[PIIMatch] = []
        for seg_id, seg_matches in by_segment.items():
            # Sort by start ascending, then length descending, then confidence descending
            sorted_m = sorted(
                seg_matches,
                key=lambda m: (m.start, -(m.end - m.start), -m.confidence),
            )
            kept: List[PIIMatch] = []
            for candidate in sorted_m:
                overlaps = False
                for existing in kept:
                    if candidate.start < existing.end and existing.start < candidate.end:
                        overlaps = True
                        break
                if not overlaps:
                    kept.append(candidate)
            resolved.extend(kept)

        return resolved
