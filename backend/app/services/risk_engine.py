"""Deterministic Risk Engine and Heuristic Signal Detection for ScamShield AI."""

import logging
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from backend.app.models.schemas import HeuristicSignals, Severity

logger = logging.getLogger("scamshield.risk")

# Heuristic indicator keyword mappings
URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "within 24 hours", "last warning",
    "final notice", "today", "expires", "instant", "immediate", "hurry",
    "action required", "time limit", "deadline", "dont delay", "don't delay"
]

THREAT_KEYWORDS = [
    "account suspended", "suspended", "account blocked", "blocked", "legal action",
    "police", "penalty", "arrest", "court", "lawsuit", "prosecution", "seized",
    "frozen", "deactivated", "terminated", "compromised", "warrant"
]

CREDENTIAL_KEYWORDS = [
    "otp", "password", "pin", "cvv", "verify your account", "verify", "login",
    "kyc", "verify kyc", "aadhaar", "pan card", "social security",
    "credentials", "passcode", "secret code", "auth code"
]

FINANCIAL_KEYWORDS = [
    "payment", "transfer", "send money", "refund", "bank account",
    "upi", "investment", "bitcoin", "crypto", "profit", "cash prize",
    "scratch card", "lottery", "deposit", "fee", "bonus", "wire"
]

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".site", ".club", ".biz", ".info", ".buzz", ".online",
    ".cf", ".ga", ".gq", ".ml", ".tk", ".icu", ".cam"
}


class HeuristicDetector:
    """Deterministic pattern and keyword detector for security signals."""

    @staticmethod
    def detect_signals(text: str) -> HeuristicSignals:
        """Analyze text and generate normalized heuristic signal strengths (0.0 - 1.0).

        Note: These scores represent deterministic heuristic signal strengths,
        NOT machine learning probabilities.
        """
        lower_text = text.lower()
        matched: Dict[str, List[str]] = {
            "urgency": [],
            "threat_language": [],
            "credential_request": [],
            "financial_request": [],
        }

        for kw in URGENCY_KEYWORDS:
            if re.search(r"\b" + re.escape(kw) + r"\b", lower_text):
                matched["urgency"].append(kw)

        for kw in THREAT_KEYWORDS:
            if re.search(r"\b" + re.escape(kw) + r"\b", lower_text):
                matched["threat_language"].append(kw)

        for kw in CREDENTIAL_KEYWORDS:
            if re.search(r"\b" + re.escape(kw) + r"\b", lower_text):
                matched["credential_request"].append(kw)

        for kw in FINANCIAL_KEYWORDS:
            if re.search(r"\b" + re.escape(kw) + r"\b", lower_text):
                matched["financial_request"].append(kw)

        # Calculate scores: diminishing returns per matched keyword
        def calculate_score(matches: List[str]) -> float:
            count = len(matches)
            if count == 0:
                return 0.0
            if count == 1:
                return 0.65
            if count == 2:
                return 0.85
            return min(1.0, 0.85 + (count - 2) * 0.05)

        urgency_score = round(calculate_score(matched["urgency"]), 2)
        threat_score = round(calculate_score(matched["threat_language"]), 2)
        credential_score = round(calculate_score(matched["credential_request"]), 2)
        financial_score = round(calculate_score(matched["financial_request"]), 2)

        return HeuristicSignals(
            urgency=urgency_score,
            threat_language=threat_score,
            credential_request=credential_score,
            financial_request=financial_score,
            matched_keywords=matched,
        )


class RiskEngine:
    """Transparent multi-factor risk scoring engine."""

    @staticmethod
    def get_severity_from_score(score: float) -> Severity:
        """Map a numeric risk score (0-100) to its discrete Severity tier.

        Boundary Tiers:
        - 0 to 20:   SAFE
        - 21 to 40:  LOW
        - 41 to 60:  MEDIUM
        - 61 to 80:  HIGH
        - 81 to 100: CRITICAL
        """
        rounded = round(score, 1)
        if rounded <= 20.0:
            return Severity.SAFE
        if rounded <= 40.0:
            return Severity.LOW
        if rounded <= 60.0:
            return Severity.MEDIUM
        if rounded <= 80.0:
            return Severity.HIGH
        return Severity.CRITICAL

    @classmethod
    def analyze_urls(cls, urls: List[str]) -> float:
        """Assess URL risk indicator score (0.0 to 1.0) deterministically without external network calls."""
        if not urls:
            return 0.0

        base_score = 0.50  # Presence of an unverified external URL
        multiplier = 1.0

        for url in urls:
            try:
                parsed = urlparse(url)
                netloc = parsed.netloc.lower()
                # Check suspicious TLDs
                if any(netloc.endswith(tld) for tld in SUSPICIOUS_TLDS):
                    multiplier = max(multiplier, 1.8)
                # Check for IP address in netloc
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", netloc):
                    multiplier = max(multiplier, 1.9)
                # Check deceptive hyphenation e.g. sbi-secure-login
                if netloc.count("-") >= 2 or ("login" in netloc and "-" in netloc):
                    multiplier = max(multiplier, 1.7)
            except Exception:
                multiplier = max(multiplier, 1.2)

        return min(1.0, round(base_score * multiplier, 2))

    @classmethod
    def calculate_risk(
        cls,
        llm_threat_score: Optional[float],
        heuristic_signals: HeuristicSignals,
        urls: List[str],
    ) -> Tuple[float, Severity]:
        """Combine AI threat analysis and deterministic security signals into a transparent score.

        Weights when LLM is available:
        - LLM threat score:     40%
        - Heuristic signals:    30%
        - URL indicators:       20%
        - Credential/Financial: 10%

        Weights in Heuristic Fallback mode (LLM unavailable):
        - Heuristic signals:    50%
        - URL indicators:       25%
        - Credential/Financial: 25%
        """
        # Composite heuristic score (average of urgency & threat language)
        heuristic_component = (heuristic_signals.urgency + heuristic_signals.threat_language) / 2.0 * 100.0

        # Credential & financial risk score
        cred_fin_component = (heuristic_signals.credential_request * 0.6 + heuristic_signals.financial_request * 0.4) * 100.0

        has_urls = bool(urls)

        if llm_threat_score is not None:
            llm_score_clamped = max(0.0, min(100.0, float(llm_threat_score)))
            if has_urls:
                url_risk_factor = cls.analyze_urls(urls)
                url_component = url_risk_factor * 100.0
                final_score = (
                    (llm_score_clamped * 0.40)
                    + (heuristic_component * 0.30)
                    + (url_component * 0.20)
                    + (cred_fin_component * 0.10)
                )
            else:
                # When URLs are absent, gracefully reallocate URL weight to LLM and Cred/Fin
                url_component = 0.0
                final_score = (
                    (llm_score_clamped * 0.55)
                    + (heuristic_component * 0.25)
                    + (cred_fin_component * 0.20)
                )
        else:
            # Deterministic heuristic fallback evaluation
            if has_urls:
                url_risk_factor = cls.analyze_urls(urls)
                url_component = url_risk_factor * 100.0
                final_score = (
                    (heuristic_component * 0.45)
                    + (url_component * 0.25)
                    + (cred_fin_component * 0.30)
                )
            else:
                url_component = 0.0
                final_score = (
                    (heuristic_component * 0.50)
                    + (cred_fin_component * 0.50)
                )

        final_score = max(0.0, min(100.0, round(final_score, 1)))
        severity = cls.get_severity_from_score(final_score)

        logger.info(
            "Calculated Risk Score: %.1f, Severity: %s (LLM: %s, Heuristics: %.1f, URL: %.1f, Cred/Fin: %.1f)",
            final_score,
            severity.value,
            str(llm_threat_score),
            heuristic_component,
            url_component,
            cred_fin_component,
        )

        return final_score, severity
