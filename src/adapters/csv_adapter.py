"""
csv_adapter.py
--------------
Comma-Separated Values (.csv) document adapter for PII Shield.
Preserves delimiters, quoting rules, and row/column alignment.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Dict, List, Tuple
import uuid

from adapters.base import DocumentAdapter, NormalizedDocument
from models import DocumentSegment, PIIMatch


class CsvAdapter(DocumentAdapter):
    """Adapter for CSV files."""

    supported_extensions = [".csv", ".tsv"]

    def extract(self, file_source: str | Path | bytes, filename: str = "data.csv") -> NormalizedDocument:
        if isinstance(file_source, bytes):
            raw_bytes = file_source
        else:
            raw_bytes = Path(file_source).read_bytes()

        text_content = raw_bytes.decode("utf-8", errors="replace")
        delimiter = "\t" if filename.endswith(".tsv") else ","

        reader = csv.reader(io.StringIO(text_content), delimiter=delimiter)
        segments: List[DocumentSegment] = []

        for row_idx, row in enumerate(reader):
            for col_idx, cell_value in enumerate(row):
                if cell_value.strip():
                    seg_id = f"csv_r{row_idx}_c{col_idx}"
                    segments.append(DocumentSegment(
                        segment_id=seg_id,
                        text=cell_value,
                        metadata={"row": row_idx, "col": col_idx, "delimiter": delimiter},
                    ))

        return NormalizedDocument(
            document_id=str(uuid.uuid4()),
            filename=filename,
            file_type="csv",
            segments=segments,
            raw_bytes=raw_bytes,
            metadata={"delimiter": delimiter},
        )

    def apply_redactions(
        self,
        doc: NormalizedDocument,
        approved_matches: List[PIIMatch],
    ) -> bytes:
        delimiter = doc.metadata.get("delimiter", ",")
        text_content = doc.raw_bytes.decode("utf-8", errors="replace")
        reader = list(csv.reader(io.StringIO(text_content), delimiter=delimiter))

        matches_by_seg: Dict[str, List[PIIMatch]] = {}
        for m in approved_matches:
            matches_by_seg.setdefault(m.segment_id, []).append(m)

        for seg in doc.segments:
            seg_matches = matches_by_seg.get(seg.segment_id, [])
            if not seg_matches:
                continue

            r_idx = seg.metadata["row"]
            c_idx = seg.metadata["col"]

            sorted_matches = sorted(seg_matches, key=lambda m: m.start, reverse=True)
            chars = list(seg.text)
            for m in sorted_matches:
                replacement = m.replacement or ""
                chars[m.start:m.end] = list(replacement)

            reader[r_idx][c_idx] = "".join(chars)

        out_io = io.StringIO()
        writer = csv.writer(out_io, delimiter=delimiter)
        for row in reader:
            writer.writerow(row)

        return out_io.getvalue().encode("utf-8")
