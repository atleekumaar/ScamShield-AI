"""Unit tests for OCR service and image security validation."""

import io
from PIL import Image
import pytest
from backend.app.services.ocr_service import (
    ImageSecurityValidator,
    MockOCRProvider,
    OCRService,
)


def create_test_image(format="PNG", size=(200, 100)) -> bytes:
    """Helper to generate in-memory valid image bytes."""
    buf = io.BytesIO()
    img = Image.new("RGB", size, color=(255, 255, 255))
    img.save(buf, format=format)
    return buf.getvalue()


class TestImageSecurityValidator:
    """Validate image upload constraints and corruption checks."""

    def test_valid_png_image(self):
        data = create_test_image(format="PNG")
        # Should not raise
        ImageSecurityValidator.validate_file("screenshot.png", "image/png", data)

    def test_valid_jpeg_image(self):
        data = create_test_image(format="JPEG")
        ImageSecurityValidator.validate_file("photo.jpg", "image/jpeg", data)

    def test_valid_webp_image(self):
        data = create_test_image(format="WEBP")
        ImageSecurityValidator.validate_file("capture.webp", "image/webp", data)

    def test_empty_image_rejected(self):
        with pytest.raises(ValueError, match="empty"):
            ImageSecurityValidator.validate_file("empty.png", "image/png", b"")

    def test_oversized_image_rejected(self):
        large_data = b"0" * (11 * 1024 * 1024)
        with pytest.raises(ValueError, match="maximum allowable size"):
            ImageSecurityValidator.validate_file("large.png", "image/png", large_data)

    def test_unsupported_mime_rejected(self):
        data = create_test_image()
        with pytest.raises(ValueError, match="Unsupported image MIME type"):
            ImageSecurityValidator.validate_file("test.pdf", "application/pdf", data)

    def test_unsupported_extension_rejected(self):
        data = create_test_image()
        with pytest.raises(ValueError, match="Unsupported image file extension"):
            ImageSecurityValidator.validate_file("malicious.exe", "image/png", data)

    def test_corrupted_image_rejected(self):
        corrupt_bytes = b"NOT_A_REAL_IMAGE_BYTES_PAYLOAD"
        with pytest.raises(ValueError, match="corrupted or not a valid image"):
            ImageSecurityValidator.validate_file("fake.png", "image/png", corrupt_bytes)


@pytest.mark.anyio
class TestOCRService:
    """Validate OCR service extraction and fallback handling."""

    async def test_mock_ocr_extraction(self):
        service = OCRService(enable_mock_fallback=True)
        img_bytes = create_test_image()
        output = await service.extract_text_from_image(img_bytes)

        assert output.text is not None
        assert len(output.text) > 0
        assert "SBI" in output.text or "account" in output.text
        assert output.provider in ["mock_ocr", "tesseract", "gemini_vision"]
        assert output.duration_ms >= 0.0

    async def test_ocr_provider_failure_when_fallback_disabled(self):
        service = OCRService(enable_mock_fallback=False)
        # Without Tesseract binary and without Gemini API key, should raise RuntimeError
        if not service.tesseract._available and not service.vision_llm:
            with pytest.raises(RuntimeError):
                await service.extract_text_from_image(create_test_image())
