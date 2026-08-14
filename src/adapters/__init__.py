from adapters.base import DocumentAdapter, NormalizedDocument
from adapters.registry import get_adapter_for_file, get_supported_extensions, register_adapter

__all__ = [
    "DocumentAdapter",
    "NormalizedDocument",
    "get_adapter_for_file",
    "get_supported_extensions",
    "register_adapter",
]
