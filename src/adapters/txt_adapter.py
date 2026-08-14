"""
txt_adapter.py
--------------
Plain text (.txt) document adapter for PII Shield.
Maintains exact line numbers, character indices, and UTF-8 encoding.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Dict
import uuid

from adapters.base import DocumentAdapter, NormalizedDocument
from models import DocumentSegment, PIIMatch


class TxtAdapter(DocumentAdapter):
    """Adapter for plain text documents."""

    supported_extensions = [".txt", ".log", ".text", ".md"]

    def extract(self, file_source: str | Path | bytes, filename: str = "document.txt") -> NormalizedDocument:
        if isinstance(file_source, bytes):
            raw_bytes = file_source
        else:
            raw_bytes = Path(file_source).read_bytes()

        text_content = raw_bytes.decode("utf-8", errors="replace")
        lines = text_content.splitlines(keepends=True)

        segments: List[DocumentSegment] = []
        for idx, line in enumerate(lines):
            seg_id = f"line_{idx}"
            segments.append(DocumentSegment(
                segment_id=seg_id,
                text=line,
                metadata={"line_number": idx + 1},
            ))

        return NormalizedDocument(
            document_id=str(uuid.uuid4()),
            filename=filename,
            file_type="txt",
            segments=segments,
            raw_bytes=raw_bytes,
            metadata={"lines": len(lines)},
        )

    def apply_redactions(
        self,
        doc: NormalizedDocument,
        approved_matches: List[PIIMatch],
    ) -> bytes:
        matches_by_seg: Dict[str, List[PIIMatch]] = {}
        for m in approved_matches:
            matches_by_seg.setdefault(m.segment_id, []).append(m)

        redacted_lines: List[str] = []
        for seg in doc.segments:
            seg_text = seg.text
            seg_matches = matches_by_seg.get(seg.segment_id, [])

            if not seg_matches:
                redacted_lines.append(seg_text)
                continue

            # Sort descending by start offset (right-to-left)
            sorted_matches = sorted(seg_matches, key=lambda m: m.start, reverse=True)
            chars = list(seg_text)
            for m in sorted_matches:
                replacement = m.replacement or ""
                chars[m.start:m.end] = list(replacement)

            redacted_lines.append("".join(chars))

        return "".join(redacted_lines).encode("utf-8")
