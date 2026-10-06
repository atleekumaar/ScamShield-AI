"""Unit tests for the RiskEngine and HeuristicDetector."""

import pytest
from backend.app.models.schemas import HeuristicSignals, Severity
from backend.app.services.risk_engine import HeuristicDetector, RiskEngine


class TestRiskEngineBoundaries:
    """Validate strict adherence to boundary definitions for risk scores."""

    @pytest.mark.parametrize(
        "score,expected_severity",
        [
            (0.0, Severity.SAFE),
            (10.0, Severity.SAFE),
            (20.0, Severity.SAFE),
            (21.0, Severity.LOW),
            (30.0, Severity.LOW),
            (40.0, Severity.LOW),
            (41.0, Severity.MEDIUM),
            (50.0, Severity.MEDIUM),
            (60.0, Severity.MEDIUM),
            (61.0, Severity.HIGH),
            (70.0, Severity.HIGH),
            (80.0, Severity.HIGH),
            (81.0, Severity.CRITICAL),
            (90.0, Severity.CRITICAL),
            (100.0, Severity.CRITICAL),
        ],
    )
    def test_severity_boundary_mappings(self, score: float, expected_severity: Severity):
        severity = RiskEngine.get_severity_from_score(score)
        assert severity == expected_severity, f"Score {score} expected {expected_severity}, got {severity}"

    def test_url_indicator_scoring(self):
        # Empty URLs
        assert RiskEngine.analyze_urls([]) == 0.0

        # Normal URL
        score_normal = RiskEngine.analyze_urls(["https://example.com/login"])
        assert 0.0 < score_normal <= 1.0

        # Suspicious TLD (.xyz) with hyphenation
        score_suspicious = RiskEngine.analyze_urls(["https://sbi-secure-login.xyz/verify"])
        assert score_suspicious > score_normal

    def test_risk_calculation_deterministic_hybrid(self):
        signals = HeuristicSignals(
            urgency=0.9,
            threat_language=0.8,
            credential_request=0.9,
            financial_request=0.7,
            matched_keywords={},
        )
        urls = ["https://sbi-secure-login.xyz/verify"]
        score_1, sev_1 = RiskEngine.calculate_risk(llm_threat_score=85.0, heuristic_signals=signals, urls=urls)
        score_2, sev_2 = RiskEngine.calculate_risk(llm_threat_score=85.0, heuristic_signals=signals, urls=urls)

        # Must be identical and deterministic
        assert score_1 == score_2
        assert sev_1 == sev_2
        assert sev_1 in [Severity.HIGH, Severity.CRITICAL]

    def test_risk_calculation_heuristic_fallback(self):
        signals = HeuristicSignals(
            urgency=0.95,
            threat_language=0.85,
            credential_request=0.9,
            financial_request=0.8,
            matched_keywords={},
        )
        urls = ["https://sbi-secure-login.xyz/verify"]
        # LLM score is None
        score, sev = RiskEngine.calculate_risk(llm_threat_score=None, heuristic_signals=signals, urls=urls)
        assert score > 60.0
        assert sev in [Severity.HIGH, Severity.CRITICAL]


class TestHeuristicDetector:
    """Validate heuristic signal extraction for keywords and triggers."""

    def test_detect_urgency_and_threat(self):
        text = "URGENT! Your account will be suspended today. Act now or face police arrest."
        signals = HeuristicDetector.detect_signals(text)
        assert signals.urgency > 0.6
        assert signals.threat_language > 0.6
        assert "urgent" in signals.matched_keywords["urgency"]
        assert "today" in signals.matched_keywords["urgency"]
        assert "suspended" in signals.matched_keywords["threat_language"]

    def test_detect_credential_and_finance(self):
        text = "Enter your OTP, PIN, and verify your KYC to claim your Rs 5000 refund and UPI payment."
        signals = HeuristicDetector.detect_signals(text)
        assert signals.credential_request > 0.6
        assert signals.financial_request > 0.6
        assert "otp" in signals.matched_keywords["credential_request"]
        assert "kyc" in signals.matched_keywords["credential_request"]
        assert "refund" in signals.matched_keywords["financial_request"]

    def test_benign_text_has_zero_signals(self):
        text = "Hey, let's meet at 3 PM tomorrow in the main conference room to discuss the project slides."
        signals = HeuristicDetector.detect_signals(text)
        assert signals.urgency == 0.0
        assert signals.threat_language == 0.0
        assert signals.credential_request == 0.0
        assert signals.financial_request == 0.0
