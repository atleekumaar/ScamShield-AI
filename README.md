# ScamShield AI

> Multimodal AI Security Analyst for digital fraud, phishing, screenshot OCR, and threat intelligence.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.12+](https://img.shields.io/badge/Python-3.12%2B-brightgreen.svg)]()
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-teal.svg)](https://fastapi.tiangolo.com)
[![Next.js: 14](https://img.shields.io/badge/Next.js-14-black.svg)](https://nextjs.org)
[![Pydantic: v2](https://img.shields.io/badge/Pydantic-v2-red.svg)](https://docs.pydantic.dev)
[![Tests: 68 Passed](https://img.shields.io/badge/Tests-68%20Passed-brightgreen.svg)]()

---

## Overview

**ScamShield AI** is an explainable cybersecurity intelligence assistant designed to protect consumers and organizations from social engineering, phishing, fake delivery notices, fraudulent job postings, malicious URLs, credential harvesting, and email fraud.

### Day 2 Milestone
Day 2 transforms ScamShield into a **multimodal threat intelligence product** supporting:
- **Text & Messages**: Instant multi-factor risk evaluation and heuristic analysis.
- **Screenshot OCR Analysis**: Upload PNG/JPEG/WEBP screenshots of SMS, WhatsApp, or fake portals.
- **URL Intelligence & Brand Lookalikes**: Structural anomaly scanning and corporate brand impersonation detection.
- **Email Forensics**: Raw `.eml` header analysis, Reply-To mismatch detection, and SPF/DKIM/DMARC status.
- **Interactive Security Dashboard**: Modern Next.js cybersecurity Operations Center interface.

---

## Multimodal Pipeline Architecture

```text
                     SCAMSHIELD AI
                          │
         ┌────────────────┼────────────────┐
         ↓                ↓                ↓
       TEXT          SCREENSHOT           URL
         │                │                │
         │               OCR               │
         │                │                │
         └────────────────┼────────────────┘
                          ↓
                  INPUT NORMALIZER
                          ↓
               THREAT ANALYSIS ENGINE
                          ↓
              URL / ENTITY INTELLIGENCE
                          ↓
                     SECURITY RAG
                          ↓
                     RISK ENGINE
                          ↓
                   EXPLAINABILITY
                          ↓
                  THREAT REPORT
                          ↓
                SECURITY DASHBOARD
```

See [`docs/architecture.md`](docs/architecture.md) for full architectural documentation.

---

## Directory Structure

```text
ScamShield-AI/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                     # FastAPI app, CORS, error handling
│   │   ├── config.py                   # Pydantic-settings config
│   │   │
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── analyze.py              # Text, Image, URL, and Email routes
│   │   │   └── health.py               # GET /health
│   │   │
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── threat_analyzer.py      # Core analysis pipeline orchestrator
│   │   │   ├── risk_engine.py          # Deterministic risk engine & heuristics
│   │   │   ├── ocr_service.py          # Image security & OCR engine
│   │   │   ├── url_intelligence.py     # Structural URL signals & brand lookalikes
│   │   │   ├── email_forensics.py      # RFC 822 email parser & header anomalies
│   │   │   ├── input_normalizer.py     # Multimodal normalization
│   │   │   ├── rag_service.py          # BM25 & Vector knowledge retriever
│   │   │   └── llm_provider.py         # LLM provider abstraction (Gemini + Mock)
│   │   │
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   └── schemas.py              # Strongly-typed Pydantic v2 domain schemas
│   │   │
│   │   └── knowledge/                  # Security knowledge base & brand signatures
│   │       ├── brand_signatures.json
│   │       ├── phishing.md
│   │       ├── social_engineering.md
│   │       ├── impersonation.md
│   │       ├── malicious_urls.md
│   │       ├── credential_theft.md
│   │       ├── financial_scams.md
│   │       └── job_scams.md
│   │
│   ├── tests/                          # 68 Automated unit & integration tests
│   │   ├── test_analyzer.py
│   │   ├── test_api.py
│   │   ├── test_dataset.py
│   │   ├── test_email_forensics.py
│   │   ├── test_health.py
│   │   ├── test_multimodal_api.py
│   │   ├── test_ocr.py
│   │   ├── test_risk_engine.py
│   │   └── test_url_intelligence.py
│   │
│   ├── requirements.txt
│   └── .env.example
│
├── frontend/                           # Next.js 14 + Tailwind CSS Security SOC Dashboard
│
├── data/
│   ├── demo_screenshots/              # Realistic demo scam screenshots
│   ├── demo_emails/                    # Sample phishing & legitimate .eml files
│   ├── demo_urls.json                  # URL evaluation test suite
│   └── sample_messages.json            # 10 malicious & 5 legitimate ground-truth samples
│
├── docs/
│   └── architecture.md                 # System architecture documentation
│
├── README.md
├── .gitignore
└── LICENSE
```

---

## Quick Start

### 1. Prerequisites
- Python 3.12+
- Node.js 18+ & npm

### 2. Backend Setup

```bash
# Clone the repository
git clone https://github.com/atleekumaar/ScamShield-AI.git
cd ScamShield-AI

# Install backend dependencies
pip install -r backend/requirements.txt

# Configure environment
cp backend/.env.example backend/.env

# Run FastAPI backend
python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

The API will be available at:
- **Base URL:** `http://localhost:8000`
- **Swagger Documentation:** `http://localhost:8000/docs`
- **Health Check:** `http://localhost:8000/health`

### 3. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

The Security Dashboard will be available at `http://localhost:3000`.

---

## API Reference

### 1. Health Check
`GET /health`
```json
{
  "status": "healthy",
  "service": "scamshield-api",
  "version": "0.2.0"
}
```

### 2. Text Analysis
`POST /api/v1/analyze`
```json
{
  "content": "URGENT! Your SBI account has been suspended today. Complete KYC verification at https://sbi-secure-login.xyz/verify",
  "input_type": "text"
}
```

### 3. Screenshot Analysis
`POST /api/v1/analyze/image` (Multipart Form Upload)
- Accepts: PNG, JPEG, WEBP ($\le 10$ MB)
- Returns: `extracted_text`, `ocr_metadata`, and `threat_report`.

### 4. URL Intelligence
`POST /api/v1/analyze/url`
```json
{
  "url": "https://sbi-secure-login.xyz/verify"
}
```
Returns:
- `signals` (Suspicious TLD, deceptive hyphenation, credential path)
- `brand_similarity` (`brand: "SBI"`, `potential_impersonation: true`)
- `risk_score`

### 5. Email Forensics
`POST /api/v1/analyze/email` (Multipart Form Upload)
- Accepts: `.eml` file ($\le 10$ MB)
- Returns: `headers` (From, Reply-To, Reply-To mismatch, SPF, DKIM, DMARC), `attachments`, and `threat_report`.

---

## Signature Feature: Attack Chain Explainability

Instead of plain text explanations, ScamShield synthesizes a visual, stepwise attack progression:

```text
ATTACK CHAIN:
[ Brand Impersonation (SBI) ]
             ↓
[ Urgency & Coercion Pressure ]
             ↓
[ Credential / KYC Solicitation ]
             ↓
[ Deceptive Link (sbi-secure-login.xyz) ]
             ↓
[ Potential Account Takeover ]
```

---

## Testing

Run all 68 automated tests:

```bash
python -m pytest backend/tests/ -v
```

All 68 tests pass in $\sim 1.5$ seconds, covering OCR validation, URL intelligence, email parsing, risk boundaries, dataset accuracy, and REST endpoints.

---

## Day 3 Roadmap

- [ ] Real-time threat feed and false positive feedback loop
- [ ] Browser extension companion for instant link inspection
- [ ] WhatsApp & SMS webhook forwarding integration
- [ ] Final hackathon demo packaging and video walkthrough

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
