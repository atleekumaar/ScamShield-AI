"""Threat analysis API router."""

import logging
from fastapi import APIRouter, HTTPException, status

from backend.app.models.schemas import AnalyzeRequest, ThreatReport
from backend.app.services.threat_analyzer import threat_analyzer

logger = logging.getLogger("scamshield.api.analyze")

router = APIRouter(prefix="/api/v1", tags=["Analysis"])


@router.post(
    "/analyze",
    response_model=ThreatReport,
    status_code=status.HTTP_200_OK,
    summary="Analyze content for scams, phishing, and cyber threats",
    description="Inspects text message, email, or communication using multimodal security pipeline (entities, heuristics, LLM, RAG, risk engine)."
)
async def analyze_threat(request: AnalyzeRequest) -> ThreatReport:
    """Analyze communication content and return comprehensive threat intelligence report."""
    try:
        report = await threat_analyzer.analyze(request)
        return report
    except ValueError as ve:
        logger.warning("Validation error in analyze endpoint: %s", str(ve))
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "INVALID_INPUT", "message": str(ve)},
        )
    except Exception as e:
        logger.error("Unexpected error during threat analysis: %s", str(e), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "INTERNAL_SERVER_ERROR", "message": "An error occurred while analyzing the threat."},
        )
