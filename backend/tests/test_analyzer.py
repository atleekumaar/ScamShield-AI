"""Unit tests for ThreatAnalyzer pipeline and entity extraction."""

import pytest
from backend.app.models.schemas import AnalyzeRequest, Severity, ThreatType
from backend.app.services.llm_provider import MockLLMProvider
from backend.app.services.threat_analyzer import ThreatAnalyzer


@pytest.fixture
def analyzer():
    """Create analyzer instance configured with deterministic mock LLM provider."""
    return ThreatAnalyzer(llm_provider=MockLLMProvider())


class TestEntityExtraction:
    """Validate URL, email, and phone extractions."""

    def test_extract_single_url(self):
        text = "Check out our portal at https://sbi-secure-login.xyz/verify immediately."
        entities = ThreatAnalyzer.extract_entities(text)
        assert len(entities.urls) == 1
        assert entities.urls[0] == "https://sbi-secure-login.xyz/verify"

    def test_extract_multiple_urls(self):
        text = "Visit http://primary-domain.com/login or secondary link https://backup.org/test for details."
        entities = ThreatAnalyzer.extract_entities(text)
        assert len(entities.urls) == 2
        assert "http://primary-domain.com/login" in entities.urls
        assert "https://backup.org/test" in entities.urls

    def test_extract_no_urls(self):
        text = "Your account statement has arrived. Please open your mobile app directly."
        entities = ThreatAnalyzer.extract_entities(text)
        assert len(entities.urls) == 0

    def test_extract_emails_and_phones(self):
        text = "Contact support@scam-alert.com or dial +1-800-555-0199 or 9876543210 right now."
        entities = ThreatAnalyzer.extract_entities(text)
        assert "support@scam-alert.com" in entities.emails
        assert len(entities.phone_numbers) >= 1

    def test_extract_known_organizations(self):
        text = "Urgent message regarding your SBI and Paytm balances."
        entities = ThreatAnalyzer.extract_entities(text)
        assert "SBI" in entities.organizations
        assert "Paytm" in entities.organizations


@pytest.mark.anyio
class TestThreatAnalyzerScenarios:
    """Test full analysis on various threat archetypes."""

    async def test_phishing_analysis(self, analyzer):
        content = (
            "URGENT! Your SBI account has been suspended due to an unverified KYC status. "
            "Complete KYC verification immediately at https://sbi-secure-login.xyz/verify"
        )
        report = await analyzer.analyze(AnalyzeRequest(content=content))

        assert report.risk_score >= 61.0
        assert report.severity in [Severity.HIGH, Severity.CRITICAL]
        assert ThreatType.PHISHING in report.threat_types
        assert ThreatType.CREDENTIAL_HARVESTING in report.threat_types
        assert len(report.extracted_entities.urls) == 1
        assert len(report.indicators) > 0
        assert len(report.recommended_actions) > 0
        assert len(report.retrieved_evidence) > 0

    async def test_legitimate_message_analysis(self, analyzer):
        content = (
            "Your monthly bank statement is now available in your official banking app. "
            "Please review your transaction summary at your convenience."
        )
        report = await analyzer.analyze(AnalyzeRequest(content=content))

        assert report.risk_score <= 40.0
        assert report.severity in [Severity.SAFE, Severity.LOW]
        assert len(report.threat_types) == 0 or ThreatType.PHISHING not in report.threat_types

    async def test_job_scam_analysis(self, analyzer):
        content = (
            "Part-time job offer! Earn $500 daily by rating hotels and YouTube videos. "
            "Pay $50 registration fee to get started today."
        )
        report = await analyzer.analyze(AnalyzeRequest(content=content))

        assert report.risk_score >= 60.0
        assert ThreatType.JOB_SCAM in report.threat_types
        assert ThreatType.FINANCIAL_FRAUD in report.threat_types
        assert any("fee" in a.lower() or "not" in a.lower() for a in report.recommended_actions)

    async def test_financial_scam_analysis(self, analyzer):
        content = (
            "Congratulations! You won Rs 5,000 cash prize. "
            "Enter your 6-digit UPI PIN to claim your refund and transfer the money."
        )
        report = await analyzer.analyze(AnalyzeRequest(content=content))

        assert report.risk_score >= 60.0
        assert ThreatType.FINANCIAL_FRAUD in report.threat_types
        assert ThreatType.CREDENTIAL_HARVESTING in report.threat_types
        assert any("upi pin" in act.lower() for act in report.recommended_actions)
