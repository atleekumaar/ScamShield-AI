"""Unit tests for URL intelligence and brand lookalike detection."""

import pytest
from backend.app.services.url_intelligence import url_intelligence_service


class TestURLIntelligence:
    """Validate structural URL signal extraction and brand impersonation detection."""

    def test_normal_legitimate_url(self):
        report = url_intelligence_service.analyze("https://github.com/explore")
        assert report.risk_score <= 20.0
        assert not report.signals.is_ip_address
        assert not report.signals.has_suspicious_tld
        assert report.reputation_status == "unavailable"

    def test_suspicious_tld_detection(self):
        report = url_intelligence_service.analyze("https://account-verify-portal.xyz/update")
        assert report.signals.has_suspicious_tld
        assert "SUSPICIOUS_TLD" in report.signals.detected_flags
        assert report.risk_score >= 25.0

    def test_raw_ip_address_url(self):
        report = url_intelligence_service.analyze("http://192.168.1.1/admin/login")
        assert report.signals.is_ip_address
        assert "RAW_IP_HOSTNAME" in report.signals.detected_flags
        assert report.risk_score >= 35.0

    def test_brand_impersonation_detection(self):
        report = url_intelligence_service.analyze("https://sbi-secure-login.xyz/verify")
        assert report.brand_similarity is not None
        assert report.brand_similarity.brand == "SBI"
        assert report.brand_similarity.potential_impersonation is True
        assert any("IMPERSONATION" in f for f in report.signals.detected_flags)
        assert report.risk_score >= 60.0

    def test_official_brand_domain_not_flagged(self):
        report = url_intelligence_service.analyze("https://onlinesbi.sbi/portal/index.html")
        assert report.brand_similarity is not None
        assert report.brand_similarity.brand == "SBI"
        assert report.brand_similarity.potential_impersonation is False
        assert report.risk_score <= 15.0

    def test_credential_path_detection(self):
        report = url_intelligence_service.analyze("https://example.com/banking/kyc/verify")
        assert report.signals.has_credential_path
        assert "CREDENTIAL_HARVESTING_PATH" in report.signals.detected_flags

    def test_unusually_long_url_detection(self):
        long_url = "https://example.com/" + "a" * 80
        report = url_intelligence_service.analyze(long_url)
        assert report.signals.is_unusually_long
        assert "UNUSUALLY_LONG_URL" in report.signals.detected_flags

    def test_url_shortener_detection(self):
        report = url_intelligence_service.analyze("https://bit.ly/3xYqz9")
        assert report.signals.is_shortened
        assert "URL_SHORTENER" in report.signals.detected_flags
