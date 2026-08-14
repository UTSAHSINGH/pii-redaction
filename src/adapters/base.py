"""
base.py
-------
Abstract base class and normalized structures for document adapters.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
import io

from models import DocumentSegment, PIIMatch


@dataclass
class NormalizedDocument:
    """Normalized document representation containing extracted segments and format metadata."""
    document_id: str
    filename: str
    file_type: str
    segments: List[DocumentSegment]
    raw_bytes: bytes
    metadata: Dict[str, Any] = field(default_factory=dict)
    native_doc: Optional[Any] = None


class DocumentAdapter(ABC):
    """Abstract interface for format-specific document processing adapters."""

    supported_extensions: List[str] = []

    @abstractmethod
    def extract(self, file_source: str | Path | bytes, filename: str = "document") -> NormalizedDocument:
        """Extract and normalize text segments from document source."""
        pass

    @abstractmethod
    def apply_redactions(
        self,
        doc: NormalizedDocument,
        approved_matches: List[PIIMatch],
    ) -> bytes:
        """Apply approved exact span redactions and return redacted document as bytes."""
        pass
