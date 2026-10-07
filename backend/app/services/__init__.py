"""Services package for ScamShield AI (Multimodal Day 2)."""

from backend.app.services.email_forensics import EmailForensicsService, email_forensics_service
from backend.app.services.input_normalizer import InputNormalizer, input_normalizer
from backend.app.services.llm_provider import GeminiProvider, LLMProvider, MockLLMProvider, get_llm_provider
from backend.app.services.ocr_service import ImageSecurityValidator, OCRService, ocr_service
from backend.app.services.rag_service import SecurityKnowledgeRAG, rag_service
from backend.app.services.risk_engine import HeuristicDetector, RiskEngine
from backend.app.services.threat_analyzer import ThreatAnalyzer, threat_analyzer
from backend.app.services.url_intelligence import URLIntelligenceService, url_intelligence_service

__all__ = [
    "EmailForensicsService",
    "email_forensics_service",
    "InputNormalizer",
    "input_normalizer",
    "GeminiProvider",
    "LLMProvider",
    "MockLLMProvider",
    "get_llm_provider",
    "ImageSecurityValidator",
    "OCRService",
    "ocr_service",
    "SecurityKnowledgeRAG",
    "rag_service",
    "HeuristicDetector",
    "RiskEngine",
    "ThreatAnalyzer",
    "threat_analyzer",
    "URLIntelligenceService",
    "url_intelligence_service",
]
