"""
registry.py
-----------
Adapter registry and factory for resolving document adapters by file extension.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional, Type

from adapters.base import DocumentAdapter
from adapters.docx_adapter import DocxAdapter
from adapters.txt_adapter import TxtAdapter
from adapters.xlsx_adapter import XlsxAdapter
from adapters.csv_adapter import CsvAdapter
from adapters.pdf_adapter import PdfAdapter

_ADAPTERS: Dict[str, DocumentAdapter] = {}


def register_adapter(adapter: DocumentAdapter) -> None:
    for ext in adapter.supported_extensions:
        _ADAPTERS[ext.lower()] = adapter


# Register default adapters
register_adapter(DocxAdapter())
register_adapter(TxtAdapter())
register_adapter(XlsxAdapter())
register_adapter(CsvAdapter())
register_adapter(PdfAdapter())


def get_adapter_for_file(filepath_or_name: str | Path) -> DocumentAdapter:
    """Return appropriate DocumentAdapter based on file extension."""
    ext = Path(filepath_or_name).suffix.lower()
    if ext not in _ADAPTERS:
        raise ValueError(
            f"Unsupported document format '{ext}'. Supported formats: {list(_ADAPTERS.keys())}"
        )
    return _ADAPTERS[ext]


def get_supported_extensions() -> list[str]:
    return list(_ADAPTERS.keys())
