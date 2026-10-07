"""Multimodal Input Normalizer transforming heterogeneous inputs into unified representation."""

import logging
from typing import Any, Dict, List, Optional

from backend.app.models.schemas import ExtractedEntities, NormalizedInput
from backend.app.services.threat_analyzer import ThreatAnalyzer

logger = logging.getLogger("scamshield.normalizer")


class InputNormalizer:
    """Normalizes Text, Screenshot OCR, URL, and Email inputs into standard representation."""

    @classmethod
    def normalize_text(
        cls,
        text: str,
        input_type: str = "text",
        source_metadata: Optional[Dict[str, Any]] = None,
    ) -> NormalizedInput:
        """Normalize raw text or OCR extracted text."""
        entities = ThreatAnalyzer.extract_entities(text)
        return NormalizedInput(
            input_type=input_type,
            raw_text=text,
            extracted_urls=entities.urls,
            extracted_emails=entities.emails,
            extracted_phone_numbers=entities.phone_numbers,
            extracted_organizations=entities.organizations,
            source_metadata=source_metadata or {},
        )

    @classmethod
    def normalize_url(
        cls,
        url: str,
        source_metadata: Optional[Dict[str, Any]] = None,
    ) -> NormalizedInput:
        """Normalize isolated URL input for threat pipeline."""
        clean_url = url.strip()
        entities = ThreatAnalyzer.extract_entities(clean_url)
        urls = entities.urls if clean_url in entities.urls else [clean_url]

        return NormalizedInput(
            input_type="url",
            raw_text=f"Inspect URL for security threats: {clean_url}",
            extracted_urls=urls,
            extracted_emails=entities.emails,
            extracted_phone_numbers=entities.phone_numbers,
            extracted_organizations=entities.organizations,
            source_metadata=source_metadata or {"url": clean_url},
        )

    @classmethod
    def normalize_email(
        cls,
        body: str,
        urls: List[str],
        headers_meta: Dict[str, Any],
        source_metadata: Optional[Dict[str, Any]] = None,
    ) -> NormalizedInput:
        """Normalize parsed email body and header anomalies."""
        entities = ThreatAnalyzer.extract_entities(body)
        combined_urls = list(dict.fromkeys(urls + entities.urls))

        meta = source_metadata or {}
        meta.update(headers_meta)

        return NormalizedInput(
            input_type="email",
            raw_text=body,
            extracted_urls=combined_urls,
            extracted_emails=entities.emails,
            extracted_phone_numbers=entities.phone_numbers,
            extracted_organizations=entities.organizations,
            source_metadata=meta,
        )


input_normalizer = InputNormalizer()
