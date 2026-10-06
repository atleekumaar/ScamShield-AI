# Credential Harvesting and Account Takeover Vectors

## Overview
Credential harvesting involves extracting authentication secrets—passwords, One-Time Passwords (OTPs), PINs, security answers, session tokens, and multi-factor authentication (MFA) prompts—to commit unauthorized account takeovers.

## Common Harvest Vectors
1. **Fake Login Portals**: Carbon-copy portals replicating single sign-on (SSO) pages, banking logins, or email portals.
2. **Reverse Proxy / Real-time Phishing (AitM)**: Adversary-in-the-Middle tools relaying live authentication challenges to capture session cookies and bypass MFA.
3. **Emergency KYC / Verification Solicitations**: Demanding immediate entry of PAN, Aadhaar, Social Security numbers, banking PINs, or card CVVs under the pretext of mandatory compliance.
4. **Vishing / Voice Social Engineering**: Scammers phoning victims claiming to be fraud investigators and urging them to "read back the OTP code received via SMS to cancel a fraudulent transaction".

## Defensive Mitigations
- Legitimate banks and service providers NEVER solicit your password, PIN, CVV, or one-time passcode over telephone, chat, or email.
- Treat any prompt requesting an OTP as an active authorization attempt on your account.
- Enable hardware security keys (FIDO2/WebAuthn) where supported to resist credential interception.
- If credentials have been compromised, immediately change passwords from a verified device and notify your service provider.
