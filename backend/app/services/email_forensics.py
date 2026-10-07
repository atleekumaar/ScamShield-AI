"""Email Forensics Service for parsing .eml files and detecting header anomalies."""

import email
from email import policy
from email.utils import parseaddr
import logging
import re
from typing import List, Optional, Tuple

from backend.app.models.schemas import (
    EmailAttachmentMeta,
    EmailHeaderAnalysis,
)

logger = logging.getLogger("scamshield.email")

URL_REGEX = re.compile(
    r"(?:https?://|www\.)[^\s/$.?#].[^\s]*",
    re.IGNORECASE
)


class EmailForensicsService:
    """Forensic email parser for RFC 822 / .eml communications."""

    @staticmethod
    def _extract_body_and_urls(msg: email.message.EmailMessage) -> Tuple[str, List[str], List[EmailAttachmentMeta]]:
        """Extract plain text / HTML body, extracted links, and attachment metadata."""
        body_parts = []
        attachments: List[EmailAttachmentMeta] = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition") or "")

                # Handle attachment
                if "attachment" in content_disposition:
                    filename = part.get_filename() or "unnamed_attachment"
                    payload = part.get_payload(decode=True) or b""
                    attachments.append(
                        EmailAttachmentMeta(
                            filename=filename,
                            content_type=content_type,
                            size_bytes=len(payload),
                        )
                    )
                    continue

                # Handle body text
                if content_type == "text/plain":
                    try:
                        content = part.get_content()
                        if isinstance(content, str):
                            body_parts.append(content)
                    except Exception:
                        pass
                elif content_type == "text/html":
                    try:
                        html_content = part.get_content()
                        if isinstance(html_content, str):
                            # Strip basic HTML tags for analysis
                            clean_text = re.sub(r"<[^>]+>", " ", html_content)
                            body_parts.append(clean_text)
                    except Exception:
                        pass
        else:
            try:
                body = msg.get_content()
                if isinstance(body, str):
                    body_parts.append(body)
            except Exception:
                pass

        full_body = "\n".join(body_parts).strip()
        raw_urls = URL_REGEX.findall(full_body)
        urls = [u.rstrip(".,;!?'\")>]}") for u in raw_urls if u.strip()]

        return full_body, list(dict.fromkeys(urls)), attachments

    @staticmethod
    def _parse_auth_headers(msg: email.message.EmailMessage) -> Tuple[str, str, str]:
        """Surface SPF, DKIM, DMARC status without assuming failure if missing."""
        spf_status = "not_present"
        dkim_status = "not_present"
        dmarc_status = "not_present"

        auth_results = msg.get("Authentication-Results", "")
        received_spf = msg.get("Received-SPF", "")

        # Check SPF
        if "spf=pass" in auth_results.lower() or received_spf.lower().startswith("pass"):
            spf_status = "pass"
        elif "spf=fail" in auth_results.lower() or received_spf.lower().startswith("fail"):
            spf_status = "fail"
        elif "spf=softfail" in auth_results.lower() or received_spf.lower().startswith("softfail"):
            spf_status = "softfail"

        # Check DKIM
        if "dkim=pass" in auth_results.lower():
            dkim_status = "pass"
        elif "dkim=fail" in auth_results.lower():
            dkim_status = "fail"
        elif msg.get("DKIM-Signature"):
            dkim_status = "signature_present"

        # Check DMARC
        if "dmarc=pass" in auth_results.lower():
            dmarc_status = "pass"
        elif "dmarc=fail" in auth_results.lower():
            dmarc_status = "fail"

        return spf_status, dkim_status, dmarc_status

    def parse_eml(self, eml_bytes: bytes) -> Tuple[EmailHeaderAnalysis, str, List[str], List[EmailAttachmentMeta]]:
        """Parse raw email bytes and evaluate header anomalies."""
        try:
            msg = email.message_from_bytes(eml_bytes, policy=policy.default)
        except Exception as e:
            raise ValueError(f"Failed to parse .eml file structure: {str(e)}")

        from_raw = msg.get("From", "")
        to_raw = msg.get("To", "")
        reply_to_raw = msg.get("Reply-To", "")
        subject = msg.get("Subject", "")
        date = msg.get("Date", "")

        from_name, from_email = parseaddr(from_raw)
        reply_to_name, reply_to_email = parseaddr(reply_to_raw)

        anomalies: List[str] = []
        reply_to_mismatch = False

        # Detect Reply-To Mismatch
        if reply_to_email and from_email:
            from_domain = from_email.split("@")[-1].lower() if "@" in from_email else ""
            reply_domain = reply_to_email.split("@")[-1].lower() if "@" in reply_to_email else ""
            if from_email.lower() != reply_to_email.lower() and from_domain != reply_domain:
                reply_to_mismatch = True
                anomalies.append(f"REPLY_TO_MISMATCH: From '{from_email}' but Reply-To is '{reply_to_email}'")

        # Detect Display Name Masquerading (e.g. 'PayPal Support <scammer@gmail.com>')
        common_brands = ["paypal", "amazon", "microsoft", "apple", "sbi", "hdfc", "google", "netflix"]
        if from_name and from_email:
            name_lower = from_name.lower()
            email_lower = from_email.lower()
            for brand in common_brands:
                if brand in name_lower and brand not in email_lower:
                    anomalies.append(f"DISPLAY_NAME_SPOOFING: Brand '{brand.title()}' in display name '{from_name}' with unrelated address '{from_email}'")
                    break

        spf_status, dkim_status, dmarc_status = self._parse_auth_headers(msg)
        if spf_status == "fail":
            anomalies.append("SPF_AUTHENTICATION_FAILED")
        if dkim_status == "fail":
            anomalies.append("DKIM_AUTHENTICATION_FAILED")
        if dmarc_status == "fail":
            anomalies.append("DMARC_AUTHENTICATION_FAILED")

        headers = EmailHeaderAnalysis(
            from_address=from_raw or from_email,
            to_address=to_raw or None,
            reply_to=reply_to_raw or None,
            subject=subject or None,
            date=date or None,
            reply_to_mismatch=reply_to_mismatch,
            spf_status=spf_status,
            dkim_status=dkim_status,
            dmarc_status=dmarc_status,
            anomalies=anomalies,
        )

        body, urls, attachments = self._extract_body_and_urls(msg)
        return headers, body, urls, attachments


# Global singleton instance
email_forensics_service = EmailForensicsService()
