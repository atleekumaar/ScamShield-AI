# ScamShield AI

> Multimodal AI Security Analyst for digital fraud, phishing, screenshot OCR, URL intelligence, and email forensics.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.12+](https://img.shields.io/badge/Python-3.12%2B-brightgreen.svg)]()
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-teal.svg)](https://fastapi.tiangolo.com)
[![Next.js: 14](https://img.shields.io/badge/Next.js-14-black.svg)](https://nextjs.org)
[![Tests: 73 Passed](https://img.shields.io/badge/Tests-73%20Passed-brightgreen.svg)]()
[![Evaluation: 100% F1](https://img.shields.io/badge/Evaluation-100%25%20F1-brightgreen.svg)]()
[![Vercel: Live](https://img.shields.io/badge/Vercel-Live-success.svg)](https://frontend-gold-seven-lmsl8sfjru.vercel.app)

---

## 🌐 Live Production Demo

- **Web Dashboard:** [https://frontend-gold-seven-lmsl8sfjru.vercel.app](https://frontend-gold-seven-lmsl8sfjru.vercel.app)
- **Architecture:** Cloud-native Next.js 14 SOC Dashboard backed by Groq AI (`qwen/qwen3.8-27b`) serverless intelligence engine + FastAPI high-performance microservices.

---

## Overview

**ScamShield AI** is an explainable cybersecurity intelligence assistant designed to protect consumers and organizations from social engineering, phishing, fake delivery notices, fraudulent job postings, malicious URLs, credential harvesting, and email fraud.

It processes **4 distinct modalities**:
1. **Text Analysis:** Detects coercive urgency, pretexting, financial lure, and fake account notices.
2. **Screenshot / OCR:** Analyzes SMS alerts, WhatsApp scams, and phishing screenshots directly from image uploads.
3. **URL Intelligence:** Evaluates brand lookalikes, suspicious TLDs, IP hosts, punycode, and deceptive paths without making dangerous external requests.
4. **Email Forensics:** Parses `.eml` headers, flags display-name spoofing, Reply-To mismatches, and inspects attachment risks.

---

## Architecture

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

---

## Clean Project Structure

```text
ScamShield-AI/
├── backend/                            # FastAPI Intelligence Backend
│   ├── app/
│   │   ├── main.py                     # App instance, CORS, routers & lifecycle
│   │   ├── config.py                   # Pydantic v2 application settings
│   │   ├── api/                        # REST API endpoints
│   │   │   ├── analyze.py              # Text, Image, URL & Email analysis routes
│   │   │   └── health.py               # Liveness & readiness probes
│   │   ├── services/                   # Core security business logic
│   │   │   ├── threat_analyzer.py      # Multimodal pipeline orchestrator
│   │   │   ├── risk_engine.py          # Deterministic risk engine & heuristic scoring
│   │   │   ├── ocr_service.py          # Secure image validation & OCR extraction
│   │   │   ├── url_intelligence.py     # Structural signals & brand lookalike analyzer
│   │   │   ├── email_forensics.py      # RFC 822 parser & email header forensics
│   │   │   ├── input_normalizer.py     # Unified payload normalization
│   │   │   ├── rag_service.py          # BM25 security knowledge retriever
│   │   │   └── llm_provider.py         # AI provider abstraction (Groq, Gemini, Mock)
│   │   ├── models/
│   │   │   └── schemas.py              # Strongly-typed domain & report schemas
│   │   └── knowledge/                  # MITRE-aligned scam taxonomy & signatures
│   │       ├── brand_signatures.json   # 15+ verified enterprise brand signatures
│   │       ├── phishing.md
│   │       ├── social_engineering.md
│   │       ├── impersonation.md
│   │       ├── malicious_urls.md
│   │       ├── credential_theft.md
│   │       ├── financial_scams.md
│   │       └── job_scams.md
│   ├── tests/                          # 73 automated tests
│   │   ├── test_analyzer.py
│   │   ├── test_api.py
│   │   ├── test_dataset.py
│   │   ├── test_email_forensics.py
│   │   ├── test_health.py
│   │   ├── test_multimodal_api.py
│   │   ├── test_ocr.py
│   │   ├── test_risk_engine.py
│   │   └── test_url_intelligence.py
│   ├── evaluation/
│   │   └── evaluate_dataset.py         # Automated quantitative benchmark runner
│   ├── requirements.txt
│   └── .env.example
│
├── frontend/                           # Next.js 14 SOC Dashboard
│   ├── src/
│   │   ├── app/
│   │   │   ├── page.tsx                # Cyber SOC Dashboard UI with live mode tabs
│   │   │   ├── layout.tsx              # Root styling & fonts
│   │   │   ├── globals.css             # Tailwind dark-mode security theme
│   │   │   └── api/v1/analyze/         # Serverless cloud API route handlers
│   │   │       ├── route.ts            # Text threat analyzer handler
│   │   │       ├── url/route.ts        # URL intelligence handler
│   │   │       ├── image/route.ts      # Screenshot OCR handler
│   │   │       └── email/route.ts      # Email forensics handler
│   │   └── lib/
│   │       └── serverAnalyzer.ts       # Cloud-native AI analyzer engine
│   ├── public/                         # Demo assets & media
│   └── package.json
│
├── data/                               # Ground-truth evaluation benchmarks
│   ├── demo_screenshots/              # Sample scam screenshots for OCR demo
│   ├── demo_emails/                    # Sample phishing & legitimate .eml files
│   ├── demo_urls.json                  # URL evaluation test suite
│   └── sample_messages.json            # 15 benchmark ground-truth samples
│
├── docs/
│   └── architecture.md                 # System architecture documentation
│
├── start.ps1                           # One-click Windows startup script
├── start.sh                            # One-click Linux / macOS startup script
├── README.md
└── LICENSE
```

---

## ⚡ Quick Start

### 1. One-Click Launch

**Windows (PowerShell):**
```powershell
.\start.ps1
```

**Linux / macOS (Bash):**
```bash
chmod +x ./start.sh
./start.sh
```

These scripts verify Python & Node dependencies, spin up the FastAPI backend on `http://localhost:8000`, and start the Next.js frontend on `http://localhost:3000`.

---

### 2. Manual Step-by-Step Setup

#### Backend Setup
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

Backend Services:
- **Base URL:** `http://localhost:8000`
- **Swagger Documentation:** `http://localhost:8000/docs`
- **Health Check:** `http://localhost:8000/health`

#### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

Dashboard will be live at `http://localhost:3000`.

---

## API Endpoints

| Method | Endpoint | Description | Payload |
|---|---|---|---|
| `GET` | `/health` | Health and readiness check | None |
| `POST` | `/api/v1/analyze` | Text threat analysis | `{"content": "...", "input_type": "text"}` |
| `POST` | `/api/v1/analyze/image` | Screenshot OCR & threat analysis | Multipart form (`file`: PNG/JPEG/WEBP) |
| `POST` | `/api/v1/analyze/url` | URL intelligence & brand lookalike | `{"url": "https://..."}` |
| `POST` | `/api/v1/analyze/email` | RFC 822 email forensics | Multipart form (`file`: .eml) |

---

## Signature Feature: Attack Chain Explainability

Instead of opaque classification labels, ScamShield synthesizes an explainable, stepwise attack progression:

```text
ATTACK CHAIN:
[ Brand Impersonation (SBI) ]
             ↓
[ Urgency & Coercion Pressure ]
             ↓
[ Credential / KYC Solicitation ]
             ↓
[ Deceptive Link (sbi-verification.xyz) ]
             ↓
[ Potential Account Takeover ]
```

---

## 📊 Quantitative Evaluation Benchmark

Run the automated evaluation benchmark on the curated test suite:

```bash
python backend/evaluation/evaluate_dataset.py
```

### Benchmark Results (15 Ground-Truth Samples):
- **Accuracy**: **100.0%** (15 / 15 correct classifications)
- **Precision**: **1.0000** (0 false positives)
- **Recall**: **1.0000** (0 false negatives)
- **F1 Score**: **1.0000**
- **Average Threat Latency**: ~35 ms

---

## 🧪 Automated Test Suite

Run the full automated test suite:

```bash
python -m pytest backend/tests/ -v
```

All **73 tests pass**, verifying:
- Image security boundaries (file types, size limits, corruption handling)
- URL signal heuristics and brand lookalike detection
- Email spoofing and authentication parsing
- Score determinism and risk classifications
- REST API contracts and schema validation

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
