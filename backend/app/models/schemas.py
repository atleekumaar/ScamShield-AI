"""Pydantic schemas and enums for ScamShield AI."""

from enum import Enum
from typing import Dict, List, Optional
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


class HealthResponse(BaseModel):
    """Health check response schema."""
    status: str = "healthy"
    service: str = "scamshield-api"
    version: str = "0.1.0"


class ErrorDetail(BaseModel):
    """Structured error message representation."""
    code: str
    message: str


class ErrorResponse(BaseModel):
    """Standardized API error envelope."""
    error: ErrorDetail
