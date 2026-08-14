"""
main.py
-------
FastAPI REST API Server for PII Shield.
Provides full enterprise document detection, human-in-the-loop review, exact-span redaction,
cryptographic integrity verification, and audit endpoints.
"""

from __future__ import annotations

import io
import os
from pathlib import Path
import shutil
import tempfile
import time
from typing import Any, Dict, List, Optional
import uuid

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from adapters.registry import get_adapter_for_file, get_supported_extensions
from domain_packs import DOMAIN_PACKS
from integrity_verifier import verify_document_integrity
from models import (
    ConfidenceTier,
    CustomDetectorConfig,
    DetectionConfig,
    DocumentAuditSummary,
    DocumentSegment,
    IntegrityReport,
    PIIMatch,
    RedactionStrategy,
    ReviewSubmission,
)
from redaction_engine import RedactionEngine
from replacement_generator import get_replacement

app = FastAPI(
    title="PII Shield API",
    description="Enterprise Document PII Detection, Review, Redaction, and Verification Engine.",
    version="2.0.0",
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ENGINE = RedactionEngine()

# Session in-memory state
# In production, this can be backed by Redis / SQLite
SESSIONS: Dict[str, Dict[str, Any]] = {}
HISTORY: List[DocumentAuditSummary] = []
TEMP_DIR = Path(tempfile.gettempdir()) / "pii_shield_uploads"
TEMP_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "PII Shield",
        "supported_formats": get_supported_extensions(),
    }


@app.get("/api/config/domains")
def get_domain_packs():
    """Return available domain protection packs."""
    return {
        "available_domains": list(DOMAIN_PACKS.keys()),
        "sample_phrases": {k: list(v)[:8] for k, v in DOMAIN_PACKS.items()},
    }


@app.post("/api/documents/upload")
async def upload_document(file: UploadFile = File(...)):
    """Upload a document for PII scanning."""
    ext = Path(file.filename).suffix.lower()
    if ext not in get_supported_extensions():
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format '{ext}'. Supported formats: {get_supported_extensions()}",
        )

    doc_id = str(uuid.uuid4())
    file_bytes = await file.read()

    # Save to temp path for verification
    temp_path = TEMP_DIR / f"{doc_id}_{file.filename}"
    temp_path.write_bytes(file_bytes)

    SESSIONS[doc_id] = {
        "doc_id": doc_id,
        "filename": file.filename,
        "file_type": ext.lstrip("."),
        "raw_bytes": file_bytes,
        "temp_path": str(temp_path),
        "created_at": time.time(),
        "status": "UPLOADED",
        "doc": None,
        "matches": [],
        "approved_matches": [],
        "redacted_bytes": None,
        "redacted_path": None,
        "integrity_report": None,
    }

    return {
        "document_id": doc_id,
        "filename": file.filename,
        "size_bytes": len(file_bytes),
        "status": "UPLOADED",
    }


@app.post("/api/documents/{doc_id}/scan")
def scan_document(doc_id: str, config: Optional[DetectionConfig] = None):
    """Scan uploaded document for PII using the specified configuration."""
    session = SESSIONS.get(doc_id)
    if not session:
        raise HTTPException(status_code=404, detail="Document not found.")

    config = config or DetectionConfig()
    start_time = time.time()

    doc, matches = ENGINE.scan_document(
        file_source=session["raw_bytes"],
        filename=session["filename"],
        config=config,
    )

    session["doc"] = doc
    session["matches"] = matches
    session["config"] = config
    session["scan_duration"] = time.time() - start_time
    session["status"] = "SCANNED"

    by_type: Dict[str, int] = {}
    for m in matches:
        by_type[m.entity_type] = by_type.get(m.entity_type, 0) + 1

    return {
        "document_id": doc_id,
        "filename": session["filename"],
        "total_segments": len(doc.segments),
        "total_detections": len(matches),
        "by_type": by_type,
        "high_confidence": sum(1 for m in matches if m.confidence_tier == ConfidenceTier.HIGH),
        "medium_confidence": sum(1 for m in matches if m.confidence_tier == ConfidenceTier.MEDIUM),
        "scan_duration_sec": round(session["scan_duration"], 3),
        "status": "SCANNED",
    }


@app.get("/api/documents/{doc_id}/detections")
def get_detections(doc_id: str):
    """Retrieve all detected PII matches for review."""
    session = SESSIONS.get(doc_id)
    if not session:
        raise HTTPException(status_code=404, detail="Document not found.")
    if session["status"] == "UPLOADED":
        raise HTTPException(status_code=400, detail="Document has not been scanned yet.")

    return {
        "document_id": doc_id,
        "filename": session["filename"],
        "matches": [m.dict() for m in session["matches"]],
    }


@app.post("/api/documents/{doc_id}/review")
def review_detections(doc_id: str, reviews: List[ReviewSubmission]):
    """Submit human-in-the-loop review actions (Approve, Reject, Edit, Change Type)."""
    session = SESSIONS.get(doc_id)
    if not session:
        raise HTTPException(status_code=404, detail="Document not found.")

    matches = session.get("matches", [])
    match_dict = {m.match_id: m for m in matches}

    applied_count = 0
    for r in reviews:
        if r.match_id in match_dict:
            m = match_dict[r.match_id]
            action_val = r.action.value if hasattr(r.action, "value") else str(r.action)
            if action_val == "APPROVE":
                m.approved = True
            elif action_val == "REJECT":
                m.approved = False
            elif action_val == "EDIT":
                if r.edited_text:
                    m.text = r.edited_text
                if r.replacement_override:
                    m.replacement = r.replacement_override
                m.approved = True
                m.user_edited = True
            elif action_val == "CHANGE_TYPE":
                if r.edited_entity_type:
                    m.entity_type = r.edited_entity_type
                m.approved = True
                m.user_edited = True
            applied_count += 1

    session["status"] = "REVIEWED"
    return {
        "document_id": doc_id,
        "reviewed_items": applied_count,
        "approved_count": sum(1 for m in matches if m.approved),
        "rejected_count": sum(1 for m in matches if not m.approved),
    }


@app.post("/api/documents/{doc_id}/redact")
def redact_document(doc_id: str):
    """Render redacted document with approved exact span replacements."""
    session = SESSIONS.get(doc_id)
    if not session or not session.get("doc"):
        raise HTTPException(status_code=404, detail="Document not ready for redaction.")

    config = session.get("config", DetectionConfig())
    redacted_bytes, approved_matches = ENGINE.apply_review_and_redact(
        doc=session["doc"],
        matches=session["matches"],
        config=config,
    )

    redacted_path = TEMP_DIR / f"redacted_{doc_id}_{session['filename']}"
    redacted_path.write_bytes(redacted_bytes)

    session["redacted_bytes"] = redacted_bytes
    session["redacted_path"] = str(redacted_path)
    session["approved_matches"] = approved_matches
    session["status"] = "REDACTED"

    return {
        "document_id": doc_id,
        "total_approved_redactions": len(approved_matches),
        "status": "REDACTED",
    }


@app.post("/api/documents/{doc_id}/verify")
def verify_document(doc_id: str):
    """Run independent cryptographic integrity verification on the redacted document."""
    session = SESSIONS.get(doc_id)
    if not session or not session.get("redacted_path"):
        raise HTTPException(status_code=400, detail="Document has not been redacted yet.")

    approved_log = [
        {
            "segment_id": m.segment_id,
            "entity_type": m.entity_type,
            "start": m.start,
            "end": m.end,
            "text": m.text,
            "replacement": m.replacement,
        }
        for m in session["approved_matches"]
    ]

    report = verify_document_integrity(
        original_file_path=session["temp_path"],
        redacted_file_path=session["redacted_path"],
        redaction_log_path_or_matches=approved_log,
    )

    session["integrity_report"] = report
    session["status"] = "VERIFIED" if report["status"] == "PASS" else "FAILED_VERIFICATION"

    # Add to session history
    audit_summary = DocumentAuditSummary(
        document_id=doc_id,
        filename=session["filename"],
        file_type=session["file_type"],
        total_segments=report["segments_checked"],
        total_detections=len(session.get("matches", [])),
        total_approved=len(session.get("approved_matches", [])),
        total_rejected=len(session.get("matches", [])) - len(session.get("approved_matches", [])),
        redaction_strategy=session.get("config", DetectionConfig()).redaction_strategy,
        integrity_status=report["status"],
        unauthorized_changed_characters=report["unauthorized_changed_characters"],
        non_pii_preservation_rate=report["non_pii_preservation_rate"],
        processing_duration_sec=round(session.get("scan_duration", 0.0), 3),
        created_at=time.strftime("%Y-%m-%d %H:%M:%S"),
    )
    HISTORY.append(audit_summary)

    return report


@app.get("/api/documents/{doc_id}/download")
def download_redacted_document(doc_id: str):
    """Download the verified redacted document file."""
    session = SESSIONS.get(doc_id)
    if not session or not session.get("redacted_path"):
        raise HTTPException(status_code=404, detail="Redacted file not found.")

    if session.get("integrity_report", {}).get("status") == "FAIL":
        raise HTTPException(
            status_code=400,
            detail="Download blocked: document failed independent integrity verification.",
        )

    p = Path(session["redacted_path"])
    return FileResponse(
        path=str(p),
        filename=f"redacted_{session['filename']}",
        media_type="application/octet-stream",
    )


@app.get("/api/history")
def get_history():
    """Retrieve history of processed documents."""
    return [h.dict() for h in reversed(HISTORY)]


@app.delete("/api/history/{doc_id}")
def delete_history_item(doc_id: str):
    """Delete a document session and its temporary files."""
    session = SESSIONS.pop(doc_id, None)
    if session:
        for p_key in ["temp_path", "redacted_path"]:
            if session.get(p_key):
                try:
                    Path(session[p_key]).unlink(missing_ok=True)
                except Exception:
                    pass
    return {"status": "DELETED", "document_id": doc_id}


# ---------------------------------------------------------------------------
# Interactive Playground Endpoint
# ---------------------------------------------------------------------------

class PlaygroundRequest(BaseModel):
    text: str
    strategy: RedactionStrategy = RedactionStrategy.SYNTHETIC
    seed: int = 42
    enabled_categories: List[str] = [
        "PERSON", "EMAIL", "PHONE", "COMPANY", "ADDRESS", "DOB", "IP_ADDRESS"
    ]


@app.post("/api/playground/redact")
def playground_redact(req: PlaygroundRequest):
    """Instantly redact a snippet of text for interactive experimentation."""
    seg = DocumentSegment(segment_id="playground", text=req.text)
    config = DetectionConfig(
        enabled_categories=req.enabled_categories,
        redaction_strategy=req.strategy,
        seed=req.seed,
    )
    matches = ENGINE.registry.scan_segments([seg], config)
    resolved = ENGINE.resolve_overlaps(matches)

    for m in resolved:
        m.replacement = get_replacement(m, req.strategy, req.seed)

    sorted_m = sorted(resolved, key=lambda m: m.start, reverse=True)
    chars = list(req.text)
    for m in sorted_m:
        chars[m.start:m.end] = list(m.replacement or "")

    return {
        "original_text": req.text,
        "redacted_text": "".join(chars),
        "matches": [m.dict() for m in resolved],
    }
