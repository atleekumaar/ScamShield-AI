"""Core Threat Analyzer orchestrating entity extraction, heuristics, LLM, RAG, and risk engine."""

from datetime import datetime, timezone
import logging
import re
import time
from typing import List, Optional, Set
import uuid

from backend.app.config import settings
from backend.app.models.schemas import (
    AnalyzeRequest,
    ExtractedEntities,
    HeuristicSignals,
    KnowledgeEvidence,
    ProcessingMetadata,
    Severity,
    ThreatIndicator,
    ThreatReport,
    ThreatType,
)
from backend.app.services.llm_provider import LLMProvider, get_llm_provider
from backend.app.services.rag_service import SecurityKnowledgeRAG, rag_service
from backend.app.services.risk_engine import HeuristicDetector, RiskEngine

logger = logging.getLogger("scamshield.analyzer")

# Regex patterns for deterministic entity extraction
URL_REGEX = re.compile(
    r"(?:https?://|www\.)[^\s/$.?#].[^\s]*",
    re.IGNORECASE
)
EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    re.IGNORECASE
)
PHONE_REGEX = re.compile(
    r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}|\b[6-9]\d{9}\b",
    re.IGNORECASE
)

KNOWN_ORGS = [
    "sbi", "hdfc", "icici", "axis bank", "paytm", "phonepe", "google pay",
    "amazon", "flipkart", "microsoft", "apple", "google", "meta", "instagram",
    "whatsapp", "telegram", "fedex", "dhl", "usps", "india post", "income tax",
    "cbdt", "police", "netflix", "spotify", "paypal", "chase", "wells fargo"
]


class ThreatAnalyzer:
    """End-to-end security threat analyzer pipeline."""

    def __init__(
        self,
        llm_provider: Optional[LLMProvider] = None,
        rag: Optional[SecurityKnowledgeRAG] = None,
    ):
        self.llm_provider = llm_provider or get_llm_provider()
        self.rag = rag or rag_service

    @staticmethod
    def extract_entities(content: str) -> ExtractedEntities:
        """Extract URLs, emails, phone numbers, and known brand mentions from text."""
        # Extract URLs
        raw_urls = URL_REGEX.findall(content)
        urls: List[str] = []
        for u in raw_urls:
            clean_u = u.rstrip(".,;!?'\")>]}")
            if clean_u:
                urls.append(clean_u)

        # Extract Emails
        emails = [e.strip() for e in EMAIL_REGEX.findall(content)]

        # Extract Phones (avoid purely short digits like dates/years)
        raw_phones = PHONE_REGEX.findall(content)
        phones: List[str] = []
        for p in raw_phones:
            p_clean = p.strip()
            digits = re.sub(r"\D", "", p_clean)
            if len(digits) >= 10:
                phones.append(p_clean)

        # Detect Brands / Organizations
        lower = content.lower()
        orgs: List[str] = []
        for org in KNOWN_ORGS:
            if re.search(r"\b" + re.escape(org) + r"\b", lower):
                orgs.append(org.upper() if len(org) <= 4 else org.title())

        return ExtractedEntities(
            urls=list(dict.fromkeys(urls)),
            emails=list(dict.fromkeys(emails)),
            phone_numbers=list(dict.fromkeys(phones)),
            organizations=list(dict.fromkeys(orgs)),
        )

    def _generate_fallback_assessment(
        self,
        content: str,
        entities: ExtractedEntities,
        heuristics: HeuristicSignals,
    ) -> dict:
        """Generate deterministic classification when LLM is unavailable or fails."""
        threat_types: Set[ThreatType] = set()
        indicators: List[ThreatIndicator] = []

        if heuristics.credential_request > 0.5:
            threat_types.add(ThreatType.CREDENTIAL_HARVESTING)
            indicators.append(
                ThreatIndicator(
                    category="CREDENTIAL_HARVESTING",
                    severity=Severity.HIGH,
                    evidence=", ".join(heuristics.matched_keywords.get("credential_request", [])),
                    description="Requests sensitive personal credentials, OTP, or account verification."
                )
            )

        if heuristics.urgency > 0.5 or heuristics.threat_language > 0.5:
            threat_types.add(ThreatType.SOCIAL_ENGINEERING)
            indicators.append(
                ThreatIndicator(
                    category="SOCIAL_ENGINEERING",
                    severity=Severity.HIGH,
                    evidence=", ".join(
                        heuristics.matched_keywords.get("urgency", []) +
                        heuristics.matched_keywords.get("threat_language", [])
                    ),
                    description="Employs artificial urgency or coercive threats to prompt hasty compliance."
                )
            )

        if entities.urls:
            threat_types.add(ThreatType.MALICIOUS_URL)
            indicators.append(
                ThreatIndicator(
                    category="SUSPICIOUS_LINK",
                    severity=Severity.HIGH if (heuristics.credential_request > 0.4 or heuristics.urgency > 0.4) else Severity.MEDIUM,
                    evidence=entities.urls[0],
                    description="Directs user to an unverified external hyperlink."
                )
            )

        if entities.organizations and (heuristics.credential_request > 0.4 or heuristics.urgency > 0.4):
            threat_types.add(ThreatType.IMPERSONATION)
            indicators.append(
                ThreatIndicator(
                    category="IMPERSONATION",
                    severity=Severity.HIGH,
                    evidence=f"Purports to represent {', '.join(entities.organizations)}",
                    description="Message references an institutional identity alongside urgent demands."
                )
            )

        if heuristics.financial_request > 0.5:
            threat_types.add(ThreatType.FINANCIAL_FRAUD)
            indicators.append(
                ThreatIndicator(
                    category="FINANCIAL_FRAUD",
                    severity=Severity.HIGH,
                    evidence=", ".join(heuristics.matched_keywords.get("financial_request", [])),
                    description="References monetary transactions, refunds, or payment transfers."
                )
            )

        if threat_types.intersection({ThreatType.CREDENTIAL_HARVESTING, ThreatType.IMPERSONATION, ThreatType.MALICIOUS_URL}):
            threat_types.add(ThreatType.PHISHING)

        if not threat_types:
            explanation = "This message demonstrates standard benign characteristics with no recognized deceptive triggers."
        else:
            threat_names = [t.value for t in threat_types]
            explanation = (
                f"Automated heuristic analysis flagged high-risk indicators for {', '.join(threat_names)}. "
                "The communication exhibits coercive language, unverified external links, or credential solicitation."
            )

        return {
            "threat_types": list(threat_types),
            "indicators": indicators,
            "explanation": explanation,
            "confidence": 0.85 if threat_types else 0.90,
        }

    @staticmethod
    def _build_recommended_actions(
        threat_types: List[ThreatType],
        severity: Severity,
        entities: ExtractedEntities,
    ) -> List[str]:
        """Generate safe, actionable defensive recommendations."""
        if severity == Severity.SAFE:
            return [
                "No immediate threat detected. Exercise standard cyber hygiene.",
                "Always access institutional services directly through their official application or bookmarked address.",
            ]

        actions = []
        if entities.urls or ThreatType.MALICIOUS_URL in threat_types:
            actions.append("DO NOT click or follow any suspicious or unverified hyperlinks.")

        if ThreatType.CREDENTIAL_HARVESTING in threat_types or ThreatType.PHISHING in threat_types:
            actions.append("DO NOT provide OTP, password, PIN, CVV, or personal identity numbers.")

        if ThreatType.IMPERSONATION in threat_types or entities.organizations:
            org_str = f"the claimed organization ({', '.join(entities.organizations)})" if entities.organizations else "the organization"
            actions.append(f"Verify the claim directly by contacting {org_str} through official, verified contact channels.")

        if ThreatType.FINANCIAL_FRAUD in threat_types:
            actions.append("DO NOT authorize incoming payment requests or enter your UPI PIN to claim prizes/refunds.")

        actions.extend([
            "Report this communication as suspicious to your email provider or mobile network operator.",
            "If credentials or payment details were already submitted, immediately notify your financial institution to freeze relevant accounts."
        ])

        return list(dict.fromkeys(actions))

    async def analyze(self, request: AnalyzeRequest) -> ThreatReport:
        """Run full threat analysis pipeline on user content."""
        start_time = time.perf_counter()
        analysis_id = str(uuid.uuid4())
        content = request.content

        logger.info("Starting threat analysis [%s] for content length: %d", analysis_id, len(content))

        # 1. Deterministic Entity Extraction
        entities = self.extract_entities(content)
        logger.info("Extracted entities: URLs=%d, Emails=%d, Phones=%d, Orgs=%s",
                    len(entities.urls), len(entities.emails), len(entities.phone_numbers), entities.organizations)

        # 2. Heuristic Signal Detection
        heuristics = HeuristicDetector.detect_signals(content)
        logger.info("Heuristic signals: Urgency=%.2f, Threat=%.2f, Cred=%.2f, Fin=%.2f",
                    heuristics.urgency, heuristics.threat_language,
                    heuristics.credential_request, heuristics.financial_request)

        # 3. LLM Analysis Call (with graceful fallback)
        llm_data = None
        analysis_mode = "hybrid_ai"
        model_used = None

        try:
            llm_data = await self.llm_provider.analyze(content, entities, heuristics)
            if llm_data:
                model_used = getattr(self.llm_provider, "model", "mock-analyst")
            else:
                logger.info("LLM returned no result. Engaging heuristic fallback mode.")
                analysis_mode = "heuristic_fallback"
        except Exception as e:
            logger.error("LLM Provider encountered error: %s. Using heuristic fallback.", str(e))
            analysis_mode = "heuristic_fallback"

        # 4. Synthesize Threat Types and Indicators
        llm_score = None
        confidence = 0.85

        if analysis_mode == "hybrid_ai" and llm_data:
            llm_score = float(llm_data.get("threat_score", 0.0))
            confidence = float(llm_data.get("confidence", 0.90))
            explanation = llm_data.get("explanation", "Analysis completed.")

            # Parse threat types
            raw_threat_types = llm_data.get("threat_types", [])
            threat_types = []
            for t_str in raw_threat_types:
                try:
                    threat_types.append(ThreatType(t_str))
                except ValueError:
                    threat_types.append(ThreatType.OTHER)

            # Incorporate additional orgs from LLM if any
            if "organizations" in llm_data and isinstance(llm_data["organizations"], list):
                combined_orgs = list(dict.fromkeys(entities.organizations + llm_data["organizations"]))
                entities.organizations = combined_orgs

            # Indicators
            indicators = []
            for ind in llm_data.get("indicators", []):
                try:
                    sev = Severity(ind.get("severity", "MEDIUM"))
                except ValueError:
                    sev = Severity.MEDIUM
                indicators.append(
                    ThreatIndicator(
                        category=ind.get("category", "INDICATOR"),
                        severity=sev,
                        evidence=ind.get("evidence", ""),
                        description=ind.get("description"),
                    )
                )
        else:
            fallback = self._generate_fallback_assessment(content, entities, heuristics)
            threat_types = fallback["threat_types"]
            indicators = fallback["indicators"]
            explanation = fallback["explanation"]
            confidence = fallback["confidence"]

        # 5. Calculate Risk Score and Severity via Risk Engine
        risk_score, severity = RiskEngine.calculate_risk(
            llm_threat_score=llm_score,
            heuristic_signals=heuristics,
            urls=entities.urls,
        )

        # 5.5 Optional Day 2 URL Intelligence
        url_intel = None
        if entities.urls:
            from backend.app.services.url_intelligence import url_intelligence_service
            url_intel = url_intelligence_service.analyze(entities.urls[0])
            if url_intel.brand_similarity and url_intel.brand_similarity.potential_impersonation:
                if ThreatType.IMPERSONATION not in threat_types:
                    threat_types.append(ThreatType.IMPERSONATION)
                indicators.append(
                    ThreatIndicator(
                        category="URL_IMPERSONATION",
                        severity=Severity.HIGH,
                        evidence=f"Domain {url_intel.hostname} mimics brand {url_intel.brand_similarity.brand}",
                        description="Potential brand impersonation detected in URL hostname.",
                    )
                )

        # 6. Retrieve Evidence from Knowledge Base (RAG)
        retrieved_evidence = self.rag.retrieve(
            query=f"{content} {' '.join(heuristics.matched_keywords.get('urgency', []))}",
            threat_types=threat_types,
            top_k=3,
        )

        # 7. Generate Defensive Recommendations
        recommended_actions = self._build_recommended_actions(threat_types, severity, entities)

        # 8. Generate Attack Chain (Day 2 Signature Feature)
        attack_chain = self._build_attack_chain(threat_types, severity, entities, url_intel)

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        metadata = ProcessingMetadata(
            analysis_mode=analysis_mode,
            model_used=model_used,
            duration_ms=elapsed_ms,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        return ThreatReport(
            analysis_id=analysis_id,
            risk_score=risk_score,
            severity=severity,
            threat_types=threat_types,
            confidence=confidence,
            indicators=indicators,
            extracted_entities=entities,
            explanation=explanation,
            recommended_actions=recommended_actions,
            retrieved_evidence=retrieved_evidence,
            processing_metadata=metadata,
            attack_chain=attack_chain,
            url_intelligence=url_intel,
        )

    @staticmethod
    def _build_attack_chain(
        threat_types: List[ThreatType],
        severity: Severity,
        entities: ExtractedEntities,
        url_intel: Optional[Any],
    ) -> List[str]:
        """Construct visual attack chain sequence for explainability."""
        if severity == Severity.SAFE:
            return ["Benign Communication", "Standard Identity Check", "No Threat Vector Detected"]

        chain: List[str] = []

        # Stage 1: Pretext / Impersonation
        if entities.organizations or ThreatType.IMPERSONATION in threat_types:
            org_name = entities.organizations[0] if entities.organizations else "Trusted Brand"
            chain.append(f"Brand Impersonation ({org_name})")
        else:
            chain.append("Unsolicited Contact / Pretext")

        # Stage 2: Psychological Coercion
        if ThreatType.SOCIAL_ENGINEERING in threat_types or ThreatType.PHISHING in threat_types:
            chain.append("Urgency & Coercion Pressure")
        elif ThreatType.JOB_SCAM in threat_types or ThreatType.FINANCIAL_FRAUD in threat_types:
            chain.append("Financial / Reward Incentive Bait")
        else:
            chain.append("Social Engineering Hook")

        # Stage 3: Exploitation Vector
        if ThreatType.CREDENTIAL_HARVESTING in threat_types:
            chain.append("Credential / KYC Solicitation")
        elif ThreatType.FINANCIAL_FRAUD in threat_types:
            chain.append("Direct Fund Transfer Request")
        else:
            chain.append("Deceptive Call to Action")

        # Stage 4: Delivery Link / Channel
        if url_intel:
            chain.append(f"Deceptive Link ({url_intel.hostname})")
        elif entities.urls:
            chain.append("Suspicious Hyperlink")
        else:
            chain.append("Off-Platform Redirection")

        # Stage 5: Adversary Impact
        if ThreatType.CREDENTIAL_HARVESTING in threat_types:
            chain.append("Potential Account Takeover")
        elif ThreatType.FINANCIAL_FRAUD in threat_types:
            chain.append("Direct Financial Loss")
        else:
            chain.append("Unauthorized Compromise")

        return chain


# Global singleton instance
threat_analyzer = ThreatAnalyzer()
