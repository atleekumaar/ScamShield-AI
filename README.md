# ScamShield AI

> Multimodal AI Security Analyst for digital fraud, phishing, and scam detection.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.12+](https://img.shields.io/badge/Python-3.12%2B-brightgreen.svg)]()
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-teal.svg)](https://fastapi.tiangolo.com)
[![Pydantic: v2](https://img.shields.io/badge/Pydantic-v2-red.svg)](https://docs.pydantic.dev)

---

## Overview

**ScamShield AI** is an explainable cybersecurity intelligence assistant designed to protect consumers and organizations from social engineering, phishing, fake delivery notices, fraudulent job postings, malicious URLs, and unauthorized financial debits.

This repository represents the **Day 1 Milestone** of a 3-day hackathon sprint, delivering a fully functional, tested, end-to-end backend threat analysis pipeline.

---

## Day 1 Architecture Pipeline

```text
User Text Input
    ↓
Input Validation & Sanitization (Pydantic v2)
    ↓
Deterministic Entity Extraction (URLs, Emails, Phones, Orgs)
    ↓
Heuristic Signal Detection (Urgency, Threat, Credential, Financial)
    ↓
LLM Provider Abstraction (Gemini / Mock / Heuristic Fallback)
    ↓
Security Knowledge Retrieval (Local Markdown RAG via BM25)
    ↓
Multi-Factor Risk Engine (Deterministic Scoring Matrix)
    ↓
Explainability & Action Generator
    ↓
Structured Threat Report (FastAPI REST API)
```

See [`docs/architecture.md`](docs/architecture.md) for full architectural documentation.

---

## Directory Structure

```text
ScamShield-AI/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                     # FastAPI application entrypoint
│   │   ├── config.py                   # Pydantic-settings environment config
│   │   │
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── analyze.py              # POST /api/v1/analyze
│   │   │   └── health.py               # GET /health
│   │   │
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── threat_analyzer.py      # Core analysis coordinator
│   │   │   ├── risk_engine.py          # Deterministic risk engine & heuristics
│   │   │   ├── rag_service.py          # Local markdown knowledge retriever
│   │   │   └── llm_provider.py         # LLM abstraction (Gemini + Mock)
│   │   │
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   └── schemas.py              # Request/Response schemas & enums
│   │   │
│   │   └── knowledge/                  # Security knowledge base
│   │       ├── phishing.md
│   │       ├── social_engineering.md
│   │       ├── impersonation.md
│   │       ├── malicious_urls.md
│   │       ├── credential_theft.md
│   │       ├── financial_scams.md
│   │       └── job_scams.md
│   │
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── test_health.py              # Health check & root tests
│   │   ├── test_risk_engine.py         # Boundary & heuristic tests
│   │   ├── test_analyzer.py            # Threat scenarios & entity extraction
│   │   ├── test_dataset.py             # Sample dataset verification
│   │   └── test_api.py                 # REST endpoint integration tests
│   │
│   ├── requirements.txt
│   └── .env.example
│
├── data/
│   └── sample_messages.json            # 10 malicious & 5 legitimate test cases
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
- Python 3.12 or higher
- pip

### 2. Installation
Clone the repository and install dependencies:

```bash
git clone https://github.com/your-username/ScamShield-AI.git
cd ScamShield-AI

# Install backend dependencies
pip install -r backend/requirements.txt
```

### 3. Environment Configuration
Copy the sample environment file:

```bash
cp backend/.env.example backend/.env
```

Configure your environment variables in `backend/.env`:

```env
ENVIRONMENT=development
PORT=8000
HOST=0.0.0.0
LOG_LEVEL=INFO

# LLM Configuration: gemini, mock
LLM_PROVIDER=gemini
LLM_API_KEY=your_gemini_api_key_here
LLM_MODEL=gemini-2.5-flash
LLM_TIMEOUT_SECONDS=10

MAX_INPUT_LENGTH=20000
```

> **Note:** If `LLM_API_KEY` is not provided or if external API calls fail, the backend automatically falls back to deterministic heuristic analysis (`analysis_mode = "heuristic_fallback"`).

### 4. Running the Server

```bash
python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

The API will be available at:
- **API Base:** `http://localhost:8000`
- **Interactive Swagger Docs:** `http://localhost:8000/docs`
- **ReDoc:** `http://localhost:8000/redoc`

---

## API Reference

### Health Check

**Endpoint:** `GET /health`

**Response (200 OK):**
```json
{
  "status": "healthy",
  "service": "scamshield-api",
  "version": "0.1.0"
}
```

---

### Threat Analysis

**Endpoint:** `POST /api/v1/analyze`

**Request Body:**
```json
{
  "content": "URGENT! Your SBI account will be suspended today. Complete KYC verification immediately at https://sbi-secure-login.xyz/verify",
  "input_type": "text",
  "language": "en"
}
```

**Response Body (200 OK):**
```json
{
  "analysis_id": "97e68cf2-0260-4966-9df3-ccebe131828f",
  "risk_score": 81.9,
  "severity": "CRITICAL",
  "threat_types": [
    "PHISHING",
    "IMPERSONATION",
    "SOCIAL_ENGINEERING",
    "CREDENTIAL_HARVESTING",
    "MALICIOUS_URL"
  ],
  "confidence": 0.90,
  "indicators": [
    {
      "category": "CREDENTIAL_HARVESTING",
      "severity": "CRITICAL",
      "evidence": "Verification / suspension demands",
      "description": "Urges user to verify credentials under threat of account action."
    },
    {
      "category": "IMPERSONATION",
      "severity": "HIGH",
      "evidence": "Claims representation of SBI",
      "description": "Message impersonates a reputable corporate or banking brand."
    },
    {
      "category": "SUSPICIOUS_LINK",
      "severity": "HIGH",
      "evidence": "https://sbi-secure-login.xyz/verify",
      "description": "Directs user to an external link of questionable origin."
    },
    {
      "category": "URGENCY",
      "severity": "HIGH",
      "evidence": "Artificial deadline pressure",
      "description": "Leverages urgency to bypass critical thinking."
    }
  ],
  "extracted_entities": {
    "urls": [
      "https://sbi-secure-login.xyz/verify"
    ],
    "emails": [],
    "phone_numbers": [],
    "organizations": [
      "SBI"
    ]
  },
  "explanation": "This message exhibits high-risk indicators characteristic of PHISHING, IMPERSONATION, CREDENTIAL_HARVESTING.",
  "recommended_actions": [
    "DO NOT click or follow any suspicious or unverified hyperlinks.",
    "DO NOT provide OTP, password, PIN, CVV, or personal identity numbers.",
    "Verify the claim directly by contacting the claimed organization (SBI) through official, verified contact channels.",
    "Report this communication as suspicious to your email provider or mobile network operator.",
    "If credentials or payment details were already submitted, immediately notify your financial institution to freeze relevant accounts."
  ],
  "retrieved_evidence": [
    {
      "source": "malicious_urls.md",
      "relevance": 0.82,
      "evidence": "## Indicators of Malicious Links 1. Typosquatting & Lookalike Domains: Minor spelling alterations, homoglyphs, or character replacements (e.g., sbi-secure-login.xyz)..."
    },
    {
      "source": "phishing.md",
      "relevance": 0.74,
      "evidence": "## Key Indicators 1. Urgent or Coercive Language: Threats of immediate account closure, legal prosecution, or service suspension within a tight timeframe..."
    }
  ],
  "processing_metadata": {
    "analysis_mode": "hybrid_ai",
    "model_used": "gemini-2.5-flash",
    "duration_ms": 142.3,
    "timestamp": "2026-10-06T18:25:36.590271Z"
  }
}
```

---

## Testing

Run the automated test suite with verbose reporting:

```bash
python -m pytest backend/tests/ -v
```

### Coverage Highlights:
- **`test_health.py`**: Health check and root metadata responses.
- **`test_risk_engine.py`**: Exact boundary tests (0, 20, 21, 40, 41, 60, 61, 80, 81, 100), heuristic signal extraction, URL heuristic checks, and fallback weighting.
- **`test_analyzer.py`**: Archetype evaluations (phishing, legitimate messages, job scams, financial scams) and entity extraction (single URL, multiple URLs, no URLs, phones, emails, organizations).
- **`test_dataset.py`**: Complete automated evaluation over the sample dataset (`data/sample_messages.json`), verifying high risk on 10 malicious samples and zero false positives on 5 legitimate samples.
- **`test_api.py`**: Integration tests covering success payloads, empty input validation (`422 INVALID_INPUT`), oversized inputs (>20,000 characters), and missing fields.

---

## Day 1 Limitations

1. **No External Domain Reputation**: URL analysis is purely heuristic (TLD check, IP hostnames, hyphenation) without external DNS, WHOIS, or threat intelligence network calls.
2. **Text-Only Ingestion**: Multimodal inputs (images, screenshots, PDF attachments) and OCR extraction are not yet integrated.
3. **Local BM25 Knowledge Base**: Uses local markdown chunks rather than high-dimensional vector embeddings with vector stores.
4. **No Persistent History**: Threat reports are evaluated on-the-fly and returned in REST responses without persistent database storage.

---

## Roadmap

### Day 2: Multimodal Intelligence & Deep URL Analysis
- [ ] OCR pipeline for screenshot analysis (Tesseract / Vision AI)
- [ ] Live URL analysis & domain age / WHOIS verification
- [ ] Email header analyzer (SPF, DKIM, DMARC parsing)
- [ ] Dense vector embeddings for security knowledge base

### Day 3: Frontend Security Dashboard & Integration
- [ ] Interactive React / Next.js security analyst dashboard
- [ ] Real-time threat feed and false positive feedback loop
- [ ] Browser extension & WhatsApp / SMS forwarding webhook
- [ ] Final demo presentation & packaging

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
