"""LLM Provider abstraction and implementations for ScamShield AI."""

from abc import ABC, abstractmethod
import json
import logging
from typing import Any, Dict, Optional

from backend.app.config import settings
from backend.app.models.schemas import ExtractedEntities, HeuristicSignals

logger = logging.getLogger("scamshield.llm")

ANALYSIS_SYSTEM_PROMPT = """You are ScamShield AI, an elite cybersecurity and fraud intelligence analyst.
Your task is to analyze the user-provided text for potential cyber threats including:
- Phishing (fake verification, account suspension threats, deceptive links)
- Impersonation (masquerading as banks, government agencies, delivery companies, employers)
- Social Engineering (artificial urgency, fear, authority coercion, scarcity)
- Credential Harvesting (solicitation of passwords, OTPs, PINs, CVVs, KYC verification)
- Financial Fraud (unauthorized money transfers, fake refunds, lottery prizes, Ponzi schemes)
- Job Scams (unrealistic high pay, upfront fee demands, informal recruitment)
- Tech Support Scams (fake virus alerts, remote access demands)

You MUST respond strictly with valid JSON conforming to the following structure:
{
  "threat_score": <float between 0.0 and 100.0>,
  "confidence": <float between 0.0 and 1.0>,
  "threat_types": [<list of strings from: PHISHING, IMPERSONATION, SOCIAL_ENGINEERING, MALICIOUS_URL, CREDENTIAL_HARVESTING, FINANCIAL_FRAUD, JOB_SCAM, MALWARE, ROMANCE_SCAM, TECH_SUPPORT_SCAM, OTHER>],
  "organizations": [<list of organization or brand names claimed or impersonated>],
  "indicators": [
    {
      "category": "<URGENCY | FEAR | IMPERSONATION | CREDENTIAL_HARVESTING | FINANCIAL_FRAUD | SUSPICIOUS_LINK | OTHER>",
      "severity": "<SAFE | LOW | MEDIUM | HIGH | CRITICAL>",
      "evidence": "<exact quote or specific phrase from input text>",
      "description": "<brief explanation of why this is dangerous>"
    }
  ],
  "explanation": "<clear explanation of why this message is safe, suspicious, or dangerous>",
  "recommended_actions": [<list of clear defensive recommendations for the user>]
}
Do not include any conversational filler, markdown fences, or text outside the JSON object.
"""


class LLMProvider(ABC):
    """Abstract interface for LLM threat analysis providers."""

    @abstractmethod
    async def analyze(
        self,
        content: str,
        extracted_entities: ExtractedEntities,
        heuristic_signals: HeuristicSignals,
    ) -> Optional[Dict[str, Any]]:
        """Analyze content and return structured JSON dictionary or None on failure."""
        pass


class GeminiProvider(LLMProvider):
    """Google Gemini LLM provider implementation using google-genai SDK."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or settings.LLM_API_KEY
        self.model = model or settings.LLM_MODEL or "gemini-2.5-flash"

    async def analyze(
        self,
        content: str,
        extracted_entities: ExtractedEntities,
        heuristic_signals: HeuristicSignals,
    ) -> Optional[Dict[str, Any]]:
        if not self.api_key:
            logger.warning("Gemini API key is not configured. Falling back to heuristic mode.")
            return None

        prompt_input = (
            f"TEXT TO ANALYZE:\n{content}\n\n"
            f"DETERMINISTIC ENTITIES DETECTED:\n"
            f"- URLs: {extracted_entities.urls}\n"
            f"- Emails: {extracted_entities.emails}\n"
            f"- Phones: {extracted_entities.phone_numbers}\n\n"
            f"HEURISTIC SIGNALS:\n"
            f"- Urgency: {heuristic_signals.urgency}\n"
            f"- Threat Language: {heuristic_signals.threat_language}\n"
            f"- Credential Request: {heuristic_signals.credential_request}\n"
            f"- Financial Request: {heuristic_signals.financial_request}\n"
        )

        try:
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=self.api_key)
            logger.info("Calling Gemini API with model %s", self.model)

            response = await client.aio.models.generate_content(
                model=self.model,
                contents=[
                    types.Content(
                        role="user",
                        parts=[types.Part.from_text(text=prompt_input)],
                    )
                ],
                config=types.GenerateContentConfig(
                    system_instruction=ANALYSIS_SYSTEM_PROMPT,
                    temperature=0.0,
                    response_mime_type="application/json",
                ),
            )

            raw_text = response.text.strip()
            # Clean possible markdown wrap if model added it
            if raw_text.startswith("```json"):
                raw_text = raw_text[7:]
            if raw_text.startswith("```"):
                raw_text = raw_text[3:]
            if raw_text.endswith("```"):
                raw_text = raw_text[:-3]

            parsed = json.loads(raw_text.strip())
            return parsed

        except Exception as e:
            logger.error("Error during Gemini analysis call: %s", str(e), exc_info=True)
            return None


class MockLLMProvider(LLMProvider):
    """Deterministic Mock LLM provider for unit tests and offline environments."""

    async def analyze(
        self,
        content: str,
        extracted_entities: ExtractedEntities,
        heuristic_signals: HeuristicSignals,
    ) -> Optional[Dict[str, Any]]:
        logger.info("Running MockLLMProvider analysis")
        content_lower = content.lower()

        is_phishing = any(k in content_lower for k in ["verify", "suspend", "kyc", "password", "blocked", "confirm your"])
        is_delivery = any(k in content_lower for k in ["fedex", "dhl", "package", "parcel", "shipping address"]) and any(k in content_lower for k in ["fee", "pay", "hold", "update"])
        is_job_scam = "earn $" in content_lower or "hotel" in content_lower or "youtube" in content_lower or "part-time" in content_lower
        is_investment = "crypto" in content_lower or "profit" in content_lower or "btc" in content_lower or "double" in content_lower
        is_tech_support = "trojan" in content_lower or "defender" in content_lower or "restart" in content_lower or "support" in content_lower and "alert" in content_lower
        is_upi = "scratch card" in content_lower or "upi pin" in content_lower or "cash prize" in content_lower
        is_gov = any(k in content_lower for k in ["tax", "penalty", "arrest warrant", "pan", "direct taxes"])
        is_social = any(k in content_lower for k in ["instagram", "copyright", "infringement", "deleted in"])
        is_refund = any(k in content_lower for k in ["refund", "charged your credit card", "unauthorized", "annual prime"])

        threat_types = []
        indicators = []
        score = 10.0
        confidence = 0.90
        orgs = []

        if "sbi" in content_lower:
            orgs.append("SBI")
        if "paytm" in content_lower:
            orgs.append("Paytm")
        if "amazon" in content_lower:
            orgs.append("Amazon")
        if "microsoft" in content_lower:
            orgs.append("Microsoft")
        if "fedex" in content_lower:
            orgs.append("FedEx")
        if "instagram" in content_lower:
            orgs.append("Instagram")

        if is_phishing:
            threat_types.extend(["PHISHING", "CREDENTIAL_HARVESTING"])
            score = max(score, 88.0)
            indicators.append({
                "category": "CREDENTIAL_HARVESTING",
                "severity": "CRITICAL",
                "evidence": "Verification / suspension demands",
                "description": "Urges user to verify credentials under threat of account action."
            })

        if is_delivery:
            threat_types.extend(["PHISHING", "IMPERSONATION", "FINANCIAL_FRAUD"])
            score = max(score, 85.0)
            indicators.append({
                "category": "FINANCIAL_FRAUD",
                "severity": "HIGH",
                "evidence": "Fake delivery fee and package hold lure",
                "description": "Requests advance payment or address update on deceptive link."
            })

        if is_gov:
            threat_types.extend(["IMPERSONATION", "SOCIAL_ENGINEERING", "PHISHING"])
            score = max(score, 88.0)
            indicators.append({
                "category": "FEAR",
                "severity": "CRITICAL",
                "evidence": "Legal penalties and arrest coercion",
                "description": "Coercive legal threats claiming to represent government agencies."
            })

        if is_social:
            threat_types.extend(["PHISHING", "IMPERSONATION", "CREDENTIAL_HARVESTING"])
            score = max(score, 86.0)
            indicators.append({
                "category": "CREDENTIAL_HARVESTING",
                "severity": "HIGH",
                "evidence": "Threat to delete account unless password confirmed",
                "description": "Deceptive copyright notice stealing social media credentials."
            })

        if is_refund:
            threat_types.extend(["FINANCIAL_FRAUD", "IMPERSONATION", "PHISHING"])
            score = max(score, 86.0)
            indicators.append({
                "category": "FINANCIAL_FRAUD",
                "severity": "HIGH",
                "evidence": "Unsolicited high billing notice with fake cancellation refund link",
                "description": "Induces panic over fictitious charge to direct victim to malicious refund portal."
            })

        if orgs and threat_types:
            threat_types.append("IMPERSONATION")
            indicators.append({
                "category": "IMPERSONATION",
                "severity": "HIGH",
                "evidence": f"Claims representation of {', '.join(orgs)}",
                "description": "Message impersonates a reputable corporate or banking brand."
            })

        if is_job_scam:
            threat_types.extend(["JOB_SCAM", "FINANCIAL_FRAUD"])
            score = max(score, 88.0)
            indicators.append({
                "category": "FINANCIAL_FRAUD",
                "severity": "HIGH",
                "evidence": "High daily pay for minimal tasks with upfront payment requirement",
                "description": "Typical task-based employment fraud soliciting upfront registration fees."
            })

        if is_investment:
            threat_types.extend(["FINANCIAL_FRAUD", "SOCIAL_ENGINEERING"])
            score = max(score, 85.0)
            indicators.append({
                "category": "FINANCIAL_FRAUD",
                "severity": "CRITICAL",
                "evidence": "Guaranteed unrealistic profit returns",
                "description": "Unrealistic high-yield cryptocurrency investment pitch."
            })

        if is_tech_support:
            threat_types.extend(["TECH_SUPPORT_SCAM", "IMPERSONATION"])
            score = max(score, 90.0)
            indicators.append({
                "category": "FEAR",
                "severity": "CRITICAL",
                "evidence": "Fake virus and compromise warnings",
                "description": "Coercive warning urging phone call to fake support line."
            })

        if is_upi:
            threat_types.extend(["FINANCIAL_FRAUD", "CREDENTIAL_HARVESTING"])
            score = max(score, 92.0)
            indicators.append({
                "category": "CREDENTIAL_HARVESTING",
                "severity": "CRITICAL",
                "evidence": "Entering UPI PIN to receive money",
                "description": "Exploiting misunderstanding of UPI PIN mechanism to debit funds."
            })

        if extracted_entities.urls:
            threat_types.append("MALICIOUS_URL")
            indicators.append({
                "category": "SUSPICIOUS_LINK",
                "severity": "HIGH",
                "evidence": extracted_entities.urls[0],
                "description": "Directs user to an external link of questionable origin."
            })

        if heuristic_signals.urgency > 0.6:
            threat_types.append("SOCIAL_ENGINEERING")
            indicators.append({
                "category": "URGENCY",
                "severity": "HIGH",
                "evidence": "Artificial deadline pressure",
                "description": "Leverages urgency to bypass critical thinking."
            })

        threat_types = list(set(threat_types))
        if not threat_types:
            explanation = "This message does not present characteristic scam indicators or deceptive urgency."
            actions = ["Normal caution is advised.", "Always verify senders through official apps."]
            score = 10.0
        else:
            explanation = f"This message exhibits high-risk indicators characteristic of {', '.join(threat_types[:3])}."
            actions = [
                "DO NOT click any embedded links or call unverified phone numbers.",
                "DO NOT provide passwords, OTPs, PINs, or confidential identity documents.",
                "Verify the organization via its official website or verified mobile application.",
                "Report this message to your security administrator or service provider."
            ]

        return {
            "threat_score": score,
            "confidence": confidence,
            "threat_types": threat_types,
            "organizations": orgs,
            "indicators": indicators,
            "explanation": explanation,
            "recommended_actions": actions,
        }


def get_llm_provider(provider_name: Optional[str] = None) -> LLMProvider:
    """Factory to create appropriate LLM provider based on config."""
    name = (provider_name or settings.LLM_PROVIDER or "gemini").lower()
    if name == "mock":
        return MockLLMProvider()
    if name == "gemini":
        return GeminiProvider()
    # If unknown, default to GeminiProvider
    return GeminiProvider()
