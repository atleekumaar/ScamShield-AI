"""Pydantic schemas and enums for ScamShield AI (Multimodal Day 2)."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    """Threat severity levels."""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatType(str, Enum):
    """Categorized threat taxonomy."""
    PHISHING = "PHISHING"
    IMPERSONATION = "IMPERSONATION"
    SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING"
    MALICIOUS_URL = "MALICIOUS_URL"
    CREDENTIAL_HARVESTING = "CREDENTIAL_HARVESTING"
    FINANCIAL_FRAUD = "FINANCIAL_FRAUD"
    JOB_SCAM = "JOB_SCAM"
    MALWARE = "MALWARE"
    ROMANCE_SCAM = "ROMANCE_SCAM"
    TECH_SUPPORT_SCAM = "TECH_SUPPORT_SCAM"
    OTHER = "OTHER"


class AnalyzeRequest(BaseModel):
    """Input payload for text threat analysis."""
    content: str = Field(
        ...,
        description="Text content of the message, email, or communication to inspect.",
        examples=["URGENT! Your bank account will be suspended today. Verify your KYC immediately at https://sbi-secure-login.xyz"]
    )
    input_type: Optional[str] = Field(
        default="text",
        description="Type of input (e.g. text, email, sms)."
    )
    language: Optional[str] = Field(
        default="en",
        description="ISO language code of the input text."
    )

    @field_validator("content")
    @classmethod
    def validate_content(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("Content must not be empty.")
        if len(stripped) > 20000:
            raise ValueError("Content exceeds maximum allowed length of 20000 characters.")
        return stripped


class ExtractedEntities(BaseModel):
    """Deterministic entity extractions from text."""
    urls: List[str] = Field(default_factory=list, description="Extracted URLs.")
    emails: List[str] = Field(default_factory=list, description="Extracted email addresses.")
    phone_numbers: List[str] = Field(default_factory=list, description="Extracted phone numbers.")
    organizations: List[str] = Field(default_factory=list, description="Identified organization or brand names.")


class ThreatIndicator(BaseModel):
    """Specific explainable risk indicator."""
    category: str = Field(..., description="Indicator category (e.g., URGENCY, IMPERSONATION).")
    severity: Severity = Field(..., description="Severity associated with indicator.")
    evidence: str = Field(..., description="Exact snippet or rationale from input text.")
    description: Optional[str] = Field(default=None, description="Detailed explanation of the security risk.")


class KnowledgeEvidence(BaseModel):
    """Retrieved intelligence citation from the security knowledge base."""
    source: str = Field(..., description="Markdown file origin.")
    relevance: float = Field(..., ge=0.0, le=1.0, description="Relevance score.")
    evidence: str = Field(..., description="Snippet from security knowledge document.")


class HeuristicSignals(BaseModel):
    """Deterministic signal strengths detected by keyword/pattern heuristics."""
    urgency: float = Field(..., ge=0.0, le=1.0, description="Heuristic score for artificial urgency.")
    threat_language: float = Field(..., ge=0.0, le=1.0, description="Heuristic score for fear/coercion language.")
    credential_request: float = Field(..., ge=0.0, le=1.0, description="Heuristic score for authentication/credential queries.")
    financial_request: float = Field(..., ge=0.0, le=1.0, description="Heuristic score for monetary/wire/refund references.")
    matched_keywords: Dict[str, List[str]] = Field(default_factory=dict, description="Keywords that triggered heuristic flags.")


class ProcessingMetadata(BaseModel):
    """Execution telemetry and diagnostics."""
    analysis_mode: str = Field(..., description="'hybrid_ai' or 'heuristic_fallback'")
    model_used: Optional[str] = Field(default=None, description="Model provider and identifier invoked.")
    duration_ms: float = Field(..., description="Processing time in milliseconds.")
    timestamp: str = Field(..., description="ISO 8601 analysis timestamp.")


# --- Day 2 URL Intelligence Schemas ---
class BrandSimilarityInfo(BaseModel):
    """Brand impersonation and lookalike evaluation."""
    brand: str
    score: float = Field(..., ge=0.0, le=1.0)
    potential_impersonation: bool = False
    official_domains: List[str] = Field(default_factory=list)


class URLSignals(BaseModel):
    """Structural indicators identified on a suspicious URL."""
    is_ip_address: bool = False
    has_suspicious_tld: bool = False
    excessive_subdomains: bool = False
    suspicious_hyphenation: bool = False
    is_punycode: bool = False
    is_shortened: bool = False
    has_credential_path: bool = False
    is_unusually_long: bool = False
    detected_flags: List[str] = Field(default_factory=list)


class URLIntelligenceReport(BaseModel):
    """Detailed structural and brand reputation evaluation of a URL."""
    url: str
    domain: str
    hostname: str
    path: str
    risk_score: float = Field(..., ge=0.0, le=100.0)
    signals: URLSignals = Field(default_factory=URLSignals)
    brand_similarity: Optional[BrandSimilarityInfo] = None
    reputation_status: str = "unavailable"


# --- Core Threat Report (Day 1 compatible, extended with Day 2 features) ---
class ThreatReport(BaseModel):
    """Structured security analyst evaluation response."""
    analysis_id: str = Field(..., description="Unique UUID for this analysis event.")
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Normalized risk score from 0 (Safe) to 100 (Critical).")
    severity: Severity = Field(..., description="Risk severity tier.")
    threat_types: List[ThreatType] = Field(default_factory=list, description="Categorized threat classifications.")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score for this assessment.")
    indicators: List[ThreatIndicator] = Field(default_factory=list, description="Structured indicators supporting evaluation.")
    extracted_entities: ExtractedEntities = Field(default_factory=ExtractedEntities, description="Entities parsed from text.")
    explanation: str = Field(..., description="Clear natural-language explanation of risk assessment.")
    recommended_actions: List[str] = Field(default_factory=list, description="Actionable defensive steps.")
    retrieved_evidence: List[KnowledgeEvidence] = Field(default_factory=list, description="Citations from security knowledge base.")
    processing_metadata: ProcessingMetadata = Field(..., description="Execution telemetry.")
    attack_chain: List[str] = Field(default_factory=list, description="Step-by-step attack progression stages.")
    url_intelligence: Optional[URLIntelligenceReport] = Field(default=None, description="Detailed URL intelligence if URLs present.")


# --- Day 2 Multimodal Normalization Schema ---
class NormalizedInput(BaseModel):
    """Unified internal representation across all modalities."""
    input_type: str = Field(..., description="'text', 'screenshot', 'url', or 'email'")
    raw_text: Optional[str] = Field(default=None)
    extracted_urls: List[str] = Field(default_factory=list)
    extracted_emails: List[str] = Field(default_factory=list)
    extracted_phone_numbers: List[str] = Field(default_factory=list)
    extracted_organizations: List[str] = Field(default_factory=list)
    source_metadata: Dict[str, Any] = Field(default_factory=dict)


# --- Day 2 Screenshot & OCR Schemas ---
class OCRMetadata(BaseModel):
    """Diagnostics from the optical character recognition service."""
    provider: str
    confidence: Optional[float] = None
    ocr_duration_ms: float


class ScreenshotAnalyzeResponse(BaseModel):
    """Response envelope for screenshot analysis."""
    input_type: str = "screenshot"
    extracted_text: str
    ocr_metadata: OCRMetadata
    threat_report: ThreatReport


# --- Day 2 URL Endpoint Schemas ---
class AnalyzeURLRequest(BaseModel):
    """Request payload for direct URL inspection."""
    url: str = Field(..., description="URL to analyze for phishing and impersonation.")

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("URL must not be empty.")
        if len(s) > 2048:
            raise ValueError("URL exceeds maximum length of 2048 characters.")
        return s


class AnalyzeURLResponse(BaseModel):
    """Response envelope for URL intelligence endpoint."""
    input_type: str = "url"
    url_intelligence: URLIntelligenceReport
    threat_report: ThreatReport


# --- Day 2 Email Forensics Schemas ---
class EmailHeaderAnalysis(BaseModel):
    """Analyzed headers and security anomalies from email message."""
    from_address: str
    to_address: Optional[str] = None
    reply_to: Optional[str] = None
    subject: Optional[str] = None
    date: Optional[str] = None
    reply_to_mismatch: bool = False
    spf_status: str = "not_present"
    dkim_status: str = "not_present"
    dmarc_status: str = "not_present"
    anomalies: List[str] = Field(default_factory=list)


class EmailAttachmentMeta(BaseModel):
    """Metadata regarding attachments present in email."""
    filename: str
    content_type: str
    size_bytes: int


class EmailAnalyzeResponse(BaseModel):
    """Response envelope for email forensic analysis."""
    input_type: str = "email"
    headers: EmailHeaderAnalysis
    extracted_urls: List[str] = Field(default_factory=list)
    attachments: List[EmailAttachmentMeta] = Field(default_factory=list)
    body_preview: str
    threat_report: ThreatReport


# --- Common Utility Schemas ---
class HealthResponse(BaseModel):
    """Health check response schema."""
    status: str = "healthy"
    service: str = "scamshield-api"
    version: str = "0.2.0"


class ErrorDetail(BaseModel):
    """Structured error message representation."""
    code: str
    message: str


class ErrorResponse(BaseModel):
    """Standardized API error envelope."""
    error: ErrorDetail
