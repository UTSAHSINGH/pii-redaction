"""
models.py
---------
Pydantic and dataclass models for PII Shield.
Defines normalized document representations, detection matches, configuration,
review actions, and integrity reports.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ConfidenceTier(str, Enum):
    HIGH = "HIGH"        # >= 0.85: Auto-approved in auto mode
    MEDIUM = "MEDIUM"    # 0.50 - 0.84: Flagged for human review
    LOW = "LOW"          # < 0.50: Discarded or manual review only


class RedactionStrategy(str, Enum):
    SYNTHETIC = "SYNTHETIC"          # Realistic fake data (Faker seeded)
    MASK = "MASK"                    # Masked characters (J*** D**, +91 XXXXX XXXXX)
    TOKEN = "TOKEN"                  # Numbered tokens (<PERSON_001>, <EMAIL_001>)
    CATEGORY_LABEL = "CATEGORY_LABEL"# Category labels ([REDACTED PERSON])


class ReviewActionType(str, Enum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    EDIT = "EDIT"
    CHANGE_TYPE = "CHANGE_TYPE"


class DocumentSegment(BaseModel):
    """Normalized segment of text extracted from any supported document format."""
    segment_id: str
    text: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    # Underlying object reference (e.g. docx paragraph or openpyxl cell)
    element_ref: Optional[Any] = None

    class Config:
        arbitrary_types_allowed = True


class PIIMatch(BaseModel):
    """Detected PII candidate span within a DocumentSegment."""
    match_id: str
    segment_id: str
    entity_type: str
    start: int
    end: int
    text: str
    confidence: float
    confidence_tier: ConfidenceTier = ConfidenceTier.HIGH
    source: str = "detector"
    context: str = ""
    replacement: Optional[str] = None
    approved: bool = True
    user_edited: bool = False
    notes: Optional[str] = None

    def overlaps(self, other: PIIMatch) -> bool:
        """Check if this match overlaps with another match in the same segment."""
        if self.segment_id != other.segment_id:
            return False
        return self.start < other.end and other.start < self.end


class CustomDetectorConfig(BaseModel):
    """User-defined custom PII regex pattern."""
    entity_name: str
    pattern: str
    confidence: float = 0.90
    replacement_strategy: Optional[RedactionStrategy] = None


class DetectionConfig(BaseModel):
    """User configuration for document PII scanning."""
    enabled_categories: List[str] = Field(
        default_factory=lambda: [
            "PERSON", "EMAIL", "PHONE", "COMPANY", "ADDRESS",
            "SSN", "CREDIT_CARD", "DOB", "IP_ADDRESS", "PAN", "UPI_ID", "IBAN"
        ]
    )
    domain_packs: List[str] = Field(default_factory=lambda: ["generic", "legal", "finance"])
    redaction_strategy: RedactionStrategy = RedactionStrategy.SYNTHETIC
    auto_redact_threshold: float = 0.85
    seed: int = 42
    custom_detectors: List[CustomDetectorConfig] = Field(default_factory=list)
    custom_protected_terms: List[str] = Field(default_factory=list)


class ReviewSubmission(BaseModel):
    """User review decisions for detected PII candidates."""
    match_id: str
    action: ReviewActionType
    edited_text: Optional[str] = None
    edited_entity_type: Optional[str] = None
    replacement_override: Optional[str] = None


class IntegrityReport(BaseModel):
    """Cryptographic output document integrity report."""
    status: str  # "PASS" or "FAIL"
    segments_checked: int
    segments_with_expected_redactions: int
    segments_with_unexpected_changes: int
    unauthorized_changed_characters: int
    total_original_characters: int
    unauthorized_change_rate: float
    non_pii_preservation_rate: float
    total_approved_spans: int
    failed_segments_sample: List[Dict[str, Any]] = Field(default_factory=list)


class DocumentAuditSummary(BaseModel):
    """Summary of a processed and verified document."""
    document_id: str
    filename: str
    file_type: str
    total_segments: int
    total_detections: int
    total_approved: int
    total_rejected: int
    redaction_strategy: RedactionStrategy
    integrity_status: str
    unauthorized_changed_characters: int
    non_pii_preservation_rate: float
    processing_duration_sec: float
    created_at: str
