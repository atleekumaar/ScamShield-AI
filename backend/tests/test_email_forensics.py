"""Unit tests for email forensics service."""

from pathlib import Path
import pytest
from backend.app.services.email_forensics import email_forensics_service


class TestEmailForensics:
    """Validate RFC 822 email parsing, header anomaly extraction, and URL discovery."""

    def test_parse_phishing_email_with_reply_to_mismatch(self):
        eml_path = Path(__file__).resolve().parent.parent.parent / "data" / "demo_emails" / "phishing_reply_to_mismatch.eml"
        with open(eml_path, "rb") as f:
            eml_bytes = f.read()

        headers, body, urls, attachments = email_forensics_service.parse_eml(eml_bytes)

        assert "security@paypal-notice-alert.com" in headers.from_address
        assert headers.reply_to == "harvest-receiver@malicious-harvest.xyz"
        assert headers.reply_to_mismatch is True
        assert any("REPLY_TO_MISMATCH" in a for a in headers.anomalies)
        assert headers.spf_status == "fail"
        assert len(urls) >= 1
        assert "paypal-security-verification.xyz" in urls[0]

    def test_parse_legitimate_email(self):
        eml_path = Path(__file__).resolve().parent.parent.parent / "data" / "demo_emails" / "legitimate_newsletter.eml"
        with open(eml_path, "rb") as f:
            eml_bytes = f.read()

        headers, body, urls, attachments = email_forensics_service.parse_eml(eml_bytes)

        assert "notifications@github.com" in headers.from_address
        assert headers.reply_to_mismatch is False
        assert headers.spf_status == "pass"
        assert headers.dkim_status == "pass"
        assert len(headers.anomalies) == 0
        assert len(urls) >= 1

    def test_missing_auth_headers_marked_not_present(self):
        simple_eml = b"""From: boss@corp.com\nTo: worker@corp.com\nSubject: Quick meeting\n\nLet's meet at 2pm."""
        headers, body, urls, attachments = email_forensics_service.parse_eml(simple_eml)

        assert headers.spf_status == "not_present"
        assert headers.dkim_status == "not_present"
        assert headers.dmarc_status == "not_present"
        assert headers.reply_to_mismatch is False
        assert "meet" in body

    def test_display_name_spoofing_detection(self):
        spoofed_eml = b"""From: "PayPal Security Dept" <attacker123@free-webmail.org>\nTo: user@example.com\nSubject: Alert\n\nVerify now."""
        headers, body, urls, attachments = email_forensics_service.parse_eml(spoofed_eml)

        assert any("DISPLAY_NAME_SPOOFING" in a for a in headers.anomalies)
