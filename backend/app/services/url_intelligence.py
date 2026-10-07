"""URL Intelligence and Brand Impersonation Analysis Service."""

from abc import ABC, abstractmethod
import json
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from backend.app.config import settings
from backend.app.models.schemas import (
    BrandSimilarityInfo,
    URLIntelligenceReport,
    URLSignals,
)

logger = logging.getLogger("scamshield.url_intel")

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".site", ".club", ".biz", ".info", ".buzz", ".online",
    ".cf", ".ga", ".gq", ".ml", ".tk", ".icu", ".cam", ".vip", ".work"
}

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "goo.gl", "tiny.cc", "rb.gy"
}

CREDENTIAL_PATH_KEYWORDS = [
    "verify", "login", "signin", "kyc", "account", "banking", "secure",
    "update", "auth", "claim", "password", "reset", "confirm", "otp",
    "authenticate", "validation", "wallet"
]


class URLReputationProvider(ABC):
    """Abstract interface for external reputation lookups."""

    @abstractmethod
    async def check_reputation(self, url: str) -> Tuple[str, Optional[Dict[str, Any]]]:
        """Return (reputation_status, metadata). Must not fabricate data."""
        pass


class FallbackReputationProvider(URLReputationProvider):
    """Safe fallback when external reputation keys are unavailable."""

    async def check_reputation(self, url: str) -> Tuple[str, Optional[Dict[str, Any]]]:
        return "unavailable", None


class URLIntelligenceService:
    """Deterministic structural URL analysis and brand lookalike detection."""

    def __init__(self, brand_signatures_path: Optional[Path] = None):
        self.brand_signatures_path = (
            brand_signatures_path or settings.KNOWLEDGE_DIR / "brand_signatures.json"
        )
        self.brands: List[Dict[str, Any]] = []
        self.reputation_provider: URLReputationProvider = FallbackReputationProvider()
        self._load_brand_signatures()

    def _load_brand_signatures(self) -> None:
        """Load known corporate brands and their official domains."""
        if not self.brand_signatures_path.exists():
            logger.warning("Brand signatures file not found at %s", self.brand_signatures_path)
            return

        try:
            with open(self.brand_signatures_path, "r", encoding="utf-8") as f:
                self.brands = json.load(f)
            logger.info("Loaded %d brand signatures for URL impersonation detection.", len(self.brands))
        except Exception as e:
            logger.error("Failed to load brand signatures: %s", str(e))

    def _extract_domain_and_hostname(self, url: str) -> Tuple[str, str, str]:
        """Normalize URL and extract (hostname, domain, path)."""
        clean_url = url.strip()
        if not re.match(r"^[a-zA-Z]+://", clean_url):
            clean_url = "http://" + clean_url

        parsed = urlparse(clean_url)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or "/"

        parts = hostname.split(".")
        if len(parts) >= 2:
            domain = ".".join(parts[-2:])
        else:
            domain = hostname

        return hostname, domain, path

    def detect_brand_similarity(self, hostname: str, domain: str) -> Optional[BrandSimilarityInfo]:
        """Detect if domain or hostname attempts to impersonate a recognized brand."""
        if not hostname or not self.brands:
            return None

        for item in self.brands:
            brand_name = item["brand"]
            aliases = [a.lower() for a in item.get("aliases", [brand_name])]
            official_domains = [d.lower() for d in item.get("official_domains", [])]

            # Check if domain is an official domain of the brand
            is_official = any(hostname == off or hostname.endswith("." + off) for off in official_domains)
            if is_official:
                return BrandSimilarityInfo(
                    brand=brand_name,
                    score=1.0,
                    potential_impersonation=False,
                    official_domains=official_domains,
                )

            # Check if any brand alias appears in the suspicious hostname
            for alias in aliases:
                # Brand match in hostname e.g. "sbi-secure-login", "paytm-kyc", "paypal"
                if alias in hostname:
                    # Calculate similarity/confidence score
                    score = 0.90 if f"-{alias}" in hostname or f"{alias}-" in hostname else 0.82
                    return BrandSimilarityInfo(
                        brand=brand_name,
                        score=score,
                        potential_impersonation=True,
                        official_domains=official_domains,
                    )

        return None

    def analyze(self, url: str) -> URLIntelligenceReport:
        """Perform comprehensive structural analysis on given URL."""
        hostname, domain, path = self._extract_domain_and_hostname(url)
        flags: List[str] = []

        # 1. IP address instead of domain
        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname))
        if is_ip:
            flags.append("RAW_IP_HOSTNAME")

        # 2. Suspicious TLD
        has_suspicious_tld = any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)
        if has_suspicious_tld:
            flags.append("SUSPICIOUS_TLD")

        # 3. Excessive subdomains
        host_parts = [p for p in hostname.split(".") if p]
        excessive_subdomains = len(host_parts) >= 4
        if excessive_subdomains:
            flags.append("EXCESSIVE_SUBDOMAINS")

        # 4. Suspicious hyphenation
        suspicious_hyphenation = hostname.count("-") >= 2 or ("-" in hostname and any(k in hostname for k in ["login", "secure", "verify", "update"]))
        if suspicious_hyphenation:
            flags.append("DECEPTIVE_HYPHENATION")

        # 5. Punycode
        is_punycode = "xn--" in hostname
        if is_punycode:
            flags.append("PUNYCODE_HOMOGLYPH")

        # 6. Shortened URL
        is_shortened = any(hostname == s or hostname.endswith("." + s) for s in KNOWN_SHORTENERS)
        if is_shortened:
            flags.append("URL_SHORTENER")

        # 7. Credential path keywords
        path_lower = path.lower()
        has_credential_path = any(re.search(r"\b" + re.escape(kw) + r"\b", path_lower) or f"/{kw}" in path_lower for kw in CREDENTIAL_PATH_KEYWORDS)
        if has_credential_path:
            flags.append("CREDENTIAL_HARVESTING_PATH")

        # 8. Unusually long URL
        is_unusually_long = len(url) > 75 or len(path) > 50
        if is_unusually_long:
            flags.append("UNUSUALLY_LONG_URL")

        # Brand impersonation check
        brand_info = self.detect_brand_similarity(hostname, domain)
        if brand_info and brand_info.potential_impersonation:
            flags.append(f"POTENTIAL_BRAND_IMPERSONATION_{brand_info.brand.upper()}")

        # Calculate structural URL Risk Score (0 - 100)
        risk = 0.0
        if is_ip:
            risk += 35.0
        if has_suspicious_tld:
            risk += 25.0
        if brand_info and brand_info.potential_impersonation:
            risk += 35.0
        if has_credential_path:
            risk += 20.0
        if excessive_subdomains:
            risk += 15.0
        if suspicious_hyphenation:
            risk += 15.0
        if is_shortened:
            risk += 15.0
        if is_punycode:
            risk += 20.0
        if is_unusually_long:
            risk += 10.0

        # If it's a verified official brand domain, cap risk score
        if brand_info and not brand_info.potential_impersonation:
            risk = min(risk, 10.0)

        risk_score = max(0.0, min(100.0, round(risk, 1)))

        signals = URLSignals(
            is_ip_address=is_ip,
            has_suspicious_tld=has_suspicious_tld,
            excessive_subdomains=excessive_subdomains,
            suspicious_hyphenation=suspicious_hyphenation,
            is_punycode=is_punycode,
            is_shortened=is_shortened,
            has_credential_path=has_credential_path,
            is_unusually_long=is_unusually_long,
            detected_flags=flags,
        )

        return URLIntelligenceReport(
            url=url,
            domain=domain,
            hostname=hostname,
            path=path,
            risk_score=risk_score,
            signals=signals,
            brand_similarity=brand_info,
            reputation_status="unavailable",
        )


# Global singleton instance
url_intelligence_service = URLIntelligenceService()
