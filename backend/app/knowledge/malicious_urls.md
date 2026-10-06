# Malicious URLs and Deceptive Domain Indicators

## Overview
Malicious links serve as the primary distribution vector for credential phishing pages, exploit kits, browser hijackers, and malware payloads.

## Indicators of Malicious Links
1. **Typosquatting & Lookalike Domains**: Minor spelling alterations, homoglyphs, or character replacements (e.g., `examp1e.com`, `paypa1-security.com`, `sbi-secure-login.xyz`).
2. **Subdomain Mimicry**: Embedding recognizable brand names as subdomains of an unrelated attacker-controlled root domain (e.g., `paypal.com.account-verify-portal.tk`).
3. **Suspicious Top-Level Domains (TLDs)**: Prevalence of cheap or abuse-prone TLDs (`.xyz`, `.top`, `.click`, `.buzz`, `.club`, `.info`) for critical financial services.
4. **URL Shorteners & Redirectors**: Obfuscating the final destination using services like bit.ly, tinyurl, or open redirects on compromised sites.
5. **Raw IP Addresses & Strange Ports**: URLs pointing to naked IPv4/IPv6 addresses or unusual ports rather than registered domain hostnames.

## Defensive Mitigations
- Inspect destination hostnames by reading right-to-left from the first single forward slash back to the double slash.
- Avoid clicking shortened or obfuscated links received in unsolicited messages.
- Never enter login credentials or payment information into unfamiliar or newly registered domains.
