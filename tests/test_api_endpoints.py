"""
test_api_endpoints.py
---------------------
API integration tests for FastAPI backend routes using TestClient.
"""

import io
import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from api.main import app

client = TestClient(app)


def test_health_endpoint():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "supported_formats" in data


def test_domain_packs_endpoint():
    resp = client.get("/api/config/domains")
    assert resp.status_code == 200
    data = resp.json()
    assert "legal" in data["available_domains"]
    assert "finance" in data["available_domains"]


def test_playground_instant_redact():
    payload = {
        "text": "Hello, my name is Dr. Sarah Wilson and email is sarah@clinic.org.",
        "strategy": "SYNTHETIC",
        "seed": 42,
        "enabled_categories": ["PERSON", "EMAIL"],
    }
    resp = client.post("/api/playground/redact", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "sarah@clinic.org" not in data["redacted_text"]
    assert len(data["matches"]) >= 1


def test_document_full_lifecycle_api():
    # 1. Upload
    file_content = b"Candidate Name: Emily Watson\nContact Email: emily.watson@gmail.com\n"
    files = {"file": ("resume.txt", io.BytesIO(file_content), "text/plain")}
    up_resp = client.post("/api/documents/upload", files=files)
    assert up_resp.status_code == 200
    doc_id = up_resp.json()["document_id"]

    # 2. Scan
    scan_resp = client.post(f"/api/documents/{doc_id}/scan")
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    assert scan_data["total_detections"] >= 1

    # 3. Get detections
    det_resp = client.get(f"/api/documents/{doc_id}/detections")
    assert det_resp.status_code == 200
    detections = det_resp.json()["matches"]
    assert len(detections) >= 1

    # 4. Review
    review_payload = [
        {"match_id": detections[0]["match_id"], "action": "APPROVE"}
    ]
    rev_resp = client.post(f"/api/documents/{doc_id}/review", json=review_payload)
    assert rev_resp.status_code == 200

    # 5. Redact
    red_resp = client.post(f"/api/documents/{doc_id}/redact")
    assert red_resp.status_code == 200

    # 6. Verify
    ver_resp = client.post(f"/api/documents/{doc_id}/verify")
    assert ver_resp.status_code == 200
    ver_data = ver_resp.json()
    assert ver_data["status"] == "PASS"
    assert ver_data["unauthorized_changed_characters"] == 0

    # 7. Download
    down_resp = client.get(f"/api/documents/{doc_id}/download")
    assert down_resp.status_code == 200
    assert len(down_resp.content) > 0

    # 8. History
    hist_resp = client.get("/api/history")
    assert hist_resp.status_code == 200
    assert len(hist_resp.json()) >= 1
