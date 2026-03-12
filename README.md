🛡️ AI-Assisted Web Vulnerability Scanner
An automated web security scanner that detects vulnerabilities, explains risks in plain language, and suggests fixes — built on Python, FastAPI, and OWASP Top 10 concepts.

📌 Problem Statement
Modern web apps often contain critical security flaws like SQL Injection, Cross-Site Scripting (XSS), and misconfigured HTTP headers.

Manual security testing is slow and requires expert knowledge.
​
This tool automates vulnerability detection and uses an AI-assisted layer to make the results easy to understand for developers of all skill levels.
🎯 Project Objectives
Scan a web application for common vulnerabilities

Detect OWASP Top 10 style risks automatically (starting with security headers)

Use AI (online) or templates (offline) to classify severity and explain each vulnerability

Generate a structured penetration testing report (JSON, later PDF)

Serve as a learning platform for ethical hacking and secure development

⚙️ Tech Stack
Layer	Technology
Backend	Python 3.11, FastAPI, Uvicorn
Scanning	requests (HTTP), Nmap (planned), BeautifulSoup (planned)
AI Engine	AI-optional: Local rule-based + LLM integration (OpenAI-compatible API)
Database	In-memory store now, PostgreSQL / MongoDB planned
Frontend	React.js (optional), HTML/JS
Reporting	JSON now, PDF later (ReportLab / WeasyPrint)
🏗️ System Architecture (AI-Optional)
text
User Input (Target URL)
        │
        ▼
┌─────────────────────┐
│    FastAPI API      │
│  /api/scan, /health │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│   Scanning Engine   │
│  ┌───────────────┐  │
│  │ Header Check  │  │  ← Uses Python requests to fetch the site
│  │ (Security     │  │     and detect missing/weak HTTP security
│  │  Headers)     │  │     headers (CSP, HSTS, XFO, etc.)[web:79][web:82]
│  └───────────────┘  │
│  ┌───────────────┐  │
│  │ Port Scanner  │  │  ← Nmap (planned)
│  │ Vuln Detector │  │  ← SQLi / XSS payloads (planned)
│  └───────────────┘  │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Result Processor   │
│  - Normalizes raw   │
│    findings into    │
│    Finding models   │
│  - Computes score   │
└────────┬────────────┘
         │
         ▼
┌────────────────────────────────────────────┐
│        AI Analysis Engine (Optional)       │
│                                            │
│  IF internet + AI_API_KEY available:       │
│    - Calls real LLM API (OpenAI-compatible│
│      or free-model gateway)               │
│    - Generates ai_explanation and         │
│      ai_mitigation for each Finding       │
│                                            │
│  ELSE (offline / no key):                  │
│    - Uses local rule-based templates to   │
│      fill ai_explanation and ai_mitigation│
└────────┬──────────────────────────────────┘
         │
         ▼
┌─────────────────────┐
│   Scan Store        │
│   - In-memory now   │
│   - DB planned      │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Report / API Layer │
│  - Returns JSON     │
│    with findings,   │
│    AI text, score   │
│  - Future: PDF, UI  │
└─────────────────────┘
📁 Project Structure
text
ai-web-vuln-scanner/
├─ backend/
│  ├─ app/
│  │  ├─ main.py                 # FastAPI app entry point
│  │  ├─ api/
│  │  │  └─ routes_scan.py       # /api/scan endpoints
│  │  ├─ schemas/
│  │  │  └─ scan.py              # Pydantic request/response models
│  │  ├─ services/
│  │  │  └─ scan_service.py      # Scan orchestration + scoring
│  │  ├─ scanners/
│  │  │  ├─ header_analyzer.py   # HTTP security header checks (implemented)
│  │  │  ├─ nmap_scanner.py      # Port scanning (planned)
│  │  │  └─ vuln_detector.py     # SQLi / XSS detection (planned)
│  │  ├─ ai_engine/
│  │  │  └─ explanation_generator.py  # Rule-based now, LLM-ready
│  │  └─ db/
│  │     └─ database.py          # DB integration (planned)
│  ├─ requirements.txt
│  └─ README.md
├─ frontend/                     # Optional React dashboard (planned)
├─ docs/
│  ├─ architecture.md
│  └─ sample-report.json
└─ README.md                     ← You are her
