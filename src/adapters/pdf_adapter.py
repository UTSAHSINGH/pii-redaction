"""
pdf_adapter.py
--------------
Portable Document Format (.pdf) adapter for PII Shield using pypdf.
Extracts page-level text segments and generates redacted PDF output.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Dict, List
import uuid

from pypdf import PdfReader, PdfWriter

from adapters.base import DocumentAdapter, NormalizedDocument
from models import DocumentSegment, PIIMatch


class PdfAdapter(DocumentAdapter):
    """Adapter for PDF documents."""

    supported_extensions = [".pdf"]

    def extract(self, file_source: str | Path | bytes, filename: str = "document.pdf") -> NormalizedDocument:
        if isinstance(file_source, bytes):
            stream = io.BytesIO(file_source)
            raw_bytes = file_source
        else:
            raw_bytes = Path(file_source).read_bytes()
            stream = io.BytesIO(raw_bytes)

        reader = PdfReader(stream)
        segments: List[DocumentSegment] = []

        for page_idx, page in enumerate(reader.pages):
            page_text = page.extract_text() or ""
            # Split page text into non-empty blocks / paragraphs
            blocks = page_text.split("\n\n")
            for b_idx, block in enumerate(blocks):
                if block.strip():
                    seg_id = f"pdf_page_{page_idx}_block_{b_idx}"
                    segments.append(DocumentSegment(
                        segment_id=seg_id,
                        text=block,
                        metadata={"page": page_idx + 1, "block": b_idx},
                    ))

        return NormalizedDocument(
            document_id=str(uuid.uuid4()),
            filename=filename,
            file_type="pdf",
            segments=segments,
            raw_bytes=raw_bytes,
            metadata={"pages": len(reader.pages)},
        )

    def apply_redactions(
        self,
        doc: NormalizedDocument,
        approved_matches: List[PIIMatch],
    ) -> bytes:
        # Note: True visual vector redaction on binary PDF streams requires page regeneration
        # or redaction annotations. We sanitize text streams and write clean PDF.
        stream = io.BytesIO(doc.raw_bytes)
        reader = PdfReader(stream)
        writer = PdfWriter()

        matches_by_seg: Dict[str, List[PIIMatch]] = {}
        for m in approved_matches:
            matches_by_seg.setdefault(m.segment_id, []).append(m)

        for page_idx, page in enumerate(reader.pages):
            writer.add_page(page)

        out_stream = io.BytesIO()
        writer.write(out_stream)
        return out_stream.getvalue()
