"""Multimodal Threat Analysis API routers (Text, Screenshot, URL, Email)."""

import logging
from typing import Optional
from fastapi import APIRouter, File, HTTPException, UploadFile, status

from backend.app.models.schemas import (
    AnalyzeRequest,
    AnalyzeURLRequest,
    AnalyzeURLResponse,
    EmailAnalyzeResponse,
    OCRMetadata,
    ScreenshotAnalyzeResponse,
    ThreatReport,
)
from backend.app.services.email_forensics import email_forensics_service
from backend.app.services.ocr_service import ImageSecurityValidator, ocr_service
from backend.app.services.threat_analyzer import threat_analyzer
from backend.app.services.url_intelligence import url_intelligence_service

logger = logging.getLogger("scamshield.api.analyze")

router = APIRouter(prefix="/api/v1", tags=["Analysis"])


# 1. Text Analysis Endpoint (Day 1 Baseline)
@router.post(
    "/analyze",
    response_model=ThreatReport,
    status_code=status.HTTP_200_OK,
    summary="Analyze text communication for cyber threats",
    description="Inspects text message, email snippet, or communication using multimodal threat pipeline.",
)
async def analyze_threat(request: AnalyzeRequest) -> ThreatReport:
    """Analyze text communication content and return comprehensive threat intelligence report."""
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
        logger.error("Unexpected error during text analysis: %s", str(e), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "INTERNAL_SERVER_ERROR", "message": "An error occurred while analyzing the threat."},
        )


# 2. Screenshot Analysis Endpoint (Day 2 Signature Capability)
@router.post(
    "/analyze/image",
    response_model=ScreenshotAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Upload and analyze screenshot of scam message",
    description="Accepts PNG/JPEG/WEBP screenshot, runs secure OCR extraction, and executes full threat pipeline.",
)
async def analyze_screenshot(
    file: UploadFile = File(..., description="Screenshot image file (PNG, JPEG, WEBP <= 10MB)"),
) -> ScreenshotAnalyzeResponse:
    """Extract text from screenshot and evaluate through threat analysis engine."""
    try:
        data = await file.read()
        # Step 1: Image Security and Format Validation
        ImageSecurityValidator.validate_file(
            filename=file.filename,
            content_type=file.content_type,
            data=data,
        )

        # Step 2: OCR Extraction
        ocr_out = await ocr_service.extract_text_from_image(data)
        if not ocr_out.text or not ocr_out.text.strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"code": "NO_TEXT_EXTRACTED", "message": "No discernible text could be extracted from image."},
            )

        # Step 3: Run existing ThreatAnalyzer on extracted text
        threat_report = await threat_analyzer.analyze(
            AnalyzeRequest(content=ocr_out.text, input_type="screenshot")
        )

        return ScreenshotAnalyzeResponse(
            input_type="screenshot",
            extracted_text=ocr_out.text,
            ocr_metadata=OCRMetadata(
                provider=ocr_out.provider,
                confidence=ocr_out.confidence,
                ocr_duration_ms=ocr_out.duration_ms,
            ),
            threat_report=threat_report,
        )

    except ValueError as ve:
        logger.warning("Validation error on image upload: %s", str(ve))
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "INVALID_IMAGE", "message": str(ve)},
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error during screenshot analysis: %s", str(e), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "SCREENSHOT_ANALYSIS_FAILED", "message": "Failed to analyze screenshot."},
        )


# 3. Direct URL Intelligence Endpoint (Day 2)
@router.post(
    "/analyze/url",
    response_model=AnalyzeURLResponse,
    status_code=status.HTTP_200_OK,
    summary="Inspect URL for phishing, homoglyphs, and brand impersonation",
    description="Analyzes structural signals, domain lookalikes, credential paths, and calculates risk score.",
)
async def analyze_url_endpoint(request: AnalyzeURLRequest) -> AnalyzeURLResponse:
    """Run structural and brand impersonation evaluation on given URL."""
    try:
        url_intel = url_intelligence_service.analyze(request.url)
        # Run threat analyzer with context
        report = await threat_analyzer.analyze(
            AnalyzeRequest(content=f"URGENT: Security alert for suspicious verification link: {request.url}", input_type="url")
        )

        return AnalyzeURLResponse(
            input_type="url",
            url_intelligence=url_intel,
            threat_report=report,
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "INVALID_URL", "message": str(ve)},
        )
    except Exception as e:
        logger.error("Error during URL analysis: %s", str(e), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "URL_ANALYSIS_FAILED", "message": "Failed to analyze URL."},
        )


# 4. Email Forensics Endpoint (Day 2)
@router.post(
    "/analyze/email",
    response_model=EmailAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Upload and analyze raw .eml email file",
    description="Parses RFC 822 email headers, flags Reply-To mismatches, extracts links, and scores risk.",
)
async def analyze_email_endpoint(
    file: UploadFile = File(..., description="Raw .eml email file"),
) -> EmailAnalyzeResponse:
    """Parse .eml file, detect header anomalies, and analyze body content."""
    try:
        data = await file.read()
        if not data or len(data) == 0:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"code": "EMPTY_EMAIL_FILE", "message": "Uploaded email file is empty."},
            )

        if len(data) > 10 * 1024 * 1024:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"code": "EMAIL_FILE_TOO_LARGE", "message": "Email file exceeds 10 MB limit."},
            )

        headers, body, urls, attachments = email_forensics_service.parse_eml(data)

        # Formulate synthesized content for threat engine
        header_context = f"Email Subject: {headers.subject or 'None'}\nFrom: {headers.from_address}\n"
        if headers.reply_to_mismatch:
            header_context += f"Suspicious Reply-To Mismatch: {headers.reply_to}\n"

        full_content = f"{header_context}\n{body}".strip()
        if not full_content:
            full_content = f"Email from {headers.from_address} with subject {headers.subject}"

        report = await threat_analyzer.analyze(
            AnalyzeRequest(content=full_content, input_type="email")
        )

        return EmailAnalyzeResponse(
            input_type="email",
            headers=headers,
            extracted_urls=urls,
            attachments=attachments,
            body_preview=body[:500] if body else "",
            threat_report=report,
        )

    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "INVALID_EMAIL", "message": str(ve)},
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error during email forensic analysis: %s", str(e), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "EMAIL_ANALYSIS_FAILED", "message": "Failed to analyze email."},
        )
