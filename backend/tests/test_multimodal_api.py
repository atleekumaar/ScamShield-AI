"""Integration tests for Day 2 Multimodal Endpoints (Image, URL, Email)."""

import io
from pathlib import Path
from PIL import Image
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.services.threat_analyzer import threat_analyzer
from backend.app.services.llm_provider import MockLLMProvider

client = TestClient(app)


def setup_module():
    """Ensure deterministic mock evaluation."""
    threat_analyzer.llm_provider = MockLLMProvider()


def create_sample_png() -> bytes:
    """Create in-memory PNG image bytes."""
    buf = io.BytesIO()
    img = Image.new("RGB", (200, 100), color=(20, 20, 20))
    img.save(buf, format="PNG")
    return buf.getvalue()


class TestMultimodalScreenshotAPI:
    """Test POST /api/v1/analyze/image endpoint."""

    def test_upload_valid_screenshot_returns_200(self):
        png_bytes = create_sample_png()
        files = {"file": ("screenshot.png", png_bytes, "image/png")}
        response = client.post("/api/v1/analyze/image", files=files)

        assert response.status_code == 200
        data = response.json()
        assert data["input_type"] == "screenshot"
        assert "extracted_text" in data
        assert "ocr_metadata" in data
        assert "threat_report" in data
        assert data["threat_report"]["risk_score"] >= 0.0

    def test_upload_unsupported_file_type_rejected(self):
        files = {"file": ("document.txt", b"plain text payload", "text/plain")}
        response = client.post("/api/v1/analyze/image", files=files)
        assert response.status_code == 422
        data = response.json()
        assert data["error"]["code"] == "INVALID_IMAGE"

    def test_upload_oversized_file_rejected(self):
        huge_bytes = b"0" * (11 * 1024 * 1024)
        files = {"file": ("huge.png", huge_bytes, "image/png")}
        response = client.post("/api/v1/analyze/image", files=files)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "INVALID_IMAGE"


class TestMultimodalURLAPI:
    """Test POST /api/v1/analyze/url endpoint."""

    def test_analyze_suspicious_url_returns_200(self):
        payload = {"url": "https://sbi-secure-login.xyz/verify"}
        response = client.post("/api/v1/analyze/url", json=payload)

        assert response.status_code == 200
        data = response.json()
        assert data["input_type"] == "url"
        assert "url_intelligence" in data
        assert data["url_intelligence"]["brand_similarity"]["brand"] == "SBI"
        assert "threat_report" in data
        assert data["threat_report"]["risk_score"] >= 60.0

    def test_analyze_legitimate_url_returns_200(self):
        payload = {"url": "https://github.com/explore"}
        response = client.post("/api/v1/analyze/url", json=payload)

        assert response.status_code == 200
        data = response.json()
        assert data["url_intelligence"]["risk_score"] <= 20.0

    def test_analyze_empty_url_rejected(self):
        payload = {"url": "   "}
        response = client.post("/api/v1/analyze/url", json=payload)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "INVALID_INPUT"


class TestMultimodalEmailAPI:
    """Test POST /api/v1/analyze/email endpoint."""

    def test_upload_valid_eml_file_returns_200(self):
        eml_content = (
            b"From: \"Bank Alert\" <service@fake-bank-alert.com>\r\n"
            b"To: victim@example.com\r\n"
            b"Reply-To: phisher@harvest.xyz\r\n"
            b"Subject: URGENT: Your account is suspended\r\n\r\n"
            b"Please verify your KYC immediately at https://sbi-secure-login.xyz/verify\r\n"
        )
        files = {"file": ("phishing.eml", eml_content, "message/rfc822")}
        response = client.post("/api/v1/analyze/email", files=files)

        assert response.status_code == 200
        data = response.json()
        assert data["input_type"] == "email"
        assert data["headers"]["reply_to_mismatch"] is True
        assert len(data["extracted_urls"]) >= 1
        assert data["threat_report"]["risk_score"] >= 60.0

    def test_upload_empty_email_rejected(self):
        files = {"file": ("empty.eml", b"", "message/rfc822")}
        response = client.post("/api/v1/analyze/email", files=files)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "EMPTY_EMAIL_FILE"
