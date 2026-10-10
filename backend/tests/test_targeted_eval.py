"""Targeted tests for Day 3 verification: robustness, fallback, edge cases, and false positive prevention."""

import io
from PIL import Image
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.models.schemas import AnalyzeRequest, Severity
from backend.app.services.llm_provider import LLMProvider
from backend.app.services.threat_analyzer import ThreatAnalyzer
from backend.app.services.url_intelligence import url_intelligence_service

client = TestClient(app)


class FailingLLMProvider(LLMProvider):
    """LLM provider that always fails to verify heuristic fallback resiliency."""

    async def analyze(self, content, extracted_entities, heuristic_signals):
        raise ConnectionError("Upstream AI Provider Unavailable (Simulated Timeout)")


class TestEdgeCasesAndRobustness:
    """Validate defensive error handling, SSRF protections, and fallback modes."""

    @pytest.mark.anyio
    async def test_llm_provider_failure_triggers_heuristic_fallback(self):
        """Verify pipeline does not crash when LLM throws, and returns heuristic fallback."""
        analyzer = ThreatAnalyzer(llm_provider=FailingLLMProvider())
        request = AnalyzeRequest(
            content="URGENT! Your account will be suspended today. Verify your KYC at https://sbi-secure-login.xyz/verify"
        )
        report = await analyzer.analyze(request)

        assert report.processing_metadata.analysis_mode == "heuristic_fallback"
        assert report.risk_score >= 60.0
        assert report.severity in [Severity.HIGH, Severity.CRITICAL]
        assert len(report.indicators) > 0
        assert len(report.recommended_actions) > 0

    def test_official_brand_domains_not_flagged_as_impersonation(self):
        """Verify that genuine official domains are never flagged as lookalike impersonation."""
        official_urls = [
            "https://www.onlinesbi.sbi/portal/index.html",
            "https://www.paypal.com/signin",
            "https://www.amazon.com/your-orders",
            "https://www.hdfcbank.com/personal",
            "https://paytm.com/recharge",
        ]
        for url in official_urls:
            report = url_intelligence_service.analyze(url)
            assert report.risk_score <= 20.0, f"False positive for {url}: {report.risk_score}"
            if report.brand_similarity:
                assert report.brand_similarity.potential_impersonation is False

    def test_malformed_url_handling(self):
        """Verify URL analyzer handles malformed and incomplete inputs without unhandled exceptions."""
        malformed_inputs = [
            "not_a_valid_url",
            "http://",
            "https:///",
            "://missing-scheme",
            "ftp://unsupported-scheme.com",
        ]
        for m in malformed_inputs:
            report = url_intelligence_service.analyze(m)
            assert report.url == m
            assert isinstance(report.risk_score, float)
            assert report.reputation_status == "unavailable"

    def test_empty_ocr_output_returns_422(self):
        """Verify uploading an image with no readable text triggers 422 NO_TEXT_EXTRACTED."""
        # Create a tiny 10x10 blank PNG image (size < 200 bytes)
        buf = io.BytesIO()
        img = Image.new("RGB", (10, 10), color=(255, 255, 255))
        img.save(buf, format="PNG")
        tiny_bytes = buf.getvalue()

        files = {"file": ("blank.png", tiny_bytes, "image/png")}
        response = client.post("/api/v1/analyze/image", files=files)
        assert response.status_code == 422
        data = response.json()
        assert data["error"]["code"] in ["NO_TEXT_EXTRACTED", "INVALID_INPUT", "INVALID_IMAGE"]

    def test_corrupted_eml_upload_handled_gracefully(self):
        """Verify malformed email data returns structured response."""
        corrupt_bytes = b"\x00\xff\xfe\x00RANDOM_BINARY_JUNK\xff\xff"
        files = {"file": ("corrupt.eml", corrupt_bytes, "message/rfc822")}
        response = client.post("/api/v1/analyze/email", files=files)
        # Should either return 200 (gracefully extracting what it can) or 422 with structured code
        assert response.status_code in [200, 422]
        if response.status_code != 200:
            assert "error" in response.json()
