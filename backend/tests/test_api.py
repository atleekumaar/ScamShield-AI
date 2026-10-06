"""API endpoint integration tests."""

from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.services.threat_analyzer import threat_analyzer
from backend.app.services.llm_provider import MockLLMProvider

client = TestClient(app)


def setup_module():
    """Ensure tests run deterministically with mock provider by default."""
    threat_analyzer.llm_provider = MockLLMProvider()


def test_analyze_endpoint_success():
    """Verify POST /api/v1/analyze returns 200 and schema compliant payload."""
    payload = {
        "content": "URGENT! Your bank account will be suspended today. Verify your KYC immediately at https://sbi-secure-login.xyz",
        "input_type": "text",
        "language": "en"
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert "analysis_id" in data
    assert "risk_score" in data
    assert "severity" in data
    assert "threat_types" in data
    assert "confidence" in data
    assert "indicators" in data
    assert "extracted_entities" in data
    assert "explanation" in data
    assert "recommended_actions" in data
    assert "retrieved_evidence" in data
    assert "processing_metadata" in data

    # Verify extracted entities
    assert "https://sbi-secure-login.xyz" in data["extracted_entities"]["urls"]
    assert data["severity"] in ["HIGH", "CRITICAL"]


def test_analyze_endpoint_empty_content_validation_failure():
    """Verify empty content triggers 422 with structured INVALID_INPUT code."""
    payload = {
        "content": "   ",
        "input_type": "text"
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 422

    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "INVALID_INPUT"
    assert "Content must not be empty" in data["error"]["message"]


def test_analyze_endpoint_oversized_content_rejected():
    """Verify content exceeding maximum limit triggers 422 with structured error."""
    oversized = "a" * 25000
    payload = {
        "content": oversized,
        "input_type": "text"
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 422

    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "INVALID_INPUT"
    assert "exceeds maximum allowed length" in data["error"]["message"]


def test_analyze_endpoint_missing_content_field():
    """Verify missing content field triggers structured validation error."""
    response = client.post("/api/v1/analyze", json={"input_type": "text"})
    assert response.status_code == 422

    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "INVALID_INPUT"
