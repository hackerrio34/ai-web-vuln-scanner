# 🛡️ AI-Assisted Web Vulnerability Scanner

> An automated web security scanner that detects vulnerabilities, explains risks in plain language, and suggests fixes — built on Python, FastAPI, and OWASP Top 10 concepts.

***

## 📌 Problem Statement

Modern web apps often contain critical security flaws like **SQL Injection**, **Cross-Site Scripting (XSS)**, and **misconfigured HTTP headers**. [owasp](https://owasp.org/www-project-top-ten/)
Manual security testing is slow and requires expert knowledge. [owasp](https://owasp.org/www-project-top-ten/)
This tool automates vulnerability detection and uses an AI-assisted layer to make the results **easy to understand** for developers of all skill levels.

***

## 🎯 Project Objectives

- Scan a web application for common vulnerabilities
- Detect OWASP Top 10 style risks automatically (starting with security headers) [owasp](https://owasp.org/www-project-secure-headers/)
- Use AI (online) or templates (offline) to classify severity and explain each vulnerability
- Generate a structured penetration testing report (JSON, later PDF)
- Serve as a **learning platform** for ethical hacking and secure development

***

## ⚙️ Tech Stack

| Layer       | Technology                                      |
|-------------|--------------------------------------------------|
| Backend     | Python 3.11, FastAPI, Uvicorn                    |
| Scanning    | `requests` (HTTP), Nmap (planned), BeautifulSoup (planned) |
| AI Engine   | AI-optional: Local rule-based + LLM integration (OpenAI-compatible API) |
| Database    | In-memory store now, PostgreSQL / MongoDB planned |
| Frontend    | React.js (optional), HTML/JS                     |
| Reporting   | JSON now, PDF later (ReportLab / WeasyPrint)     |

***

## 🏗️ System Architecture (AI-Optional)

```text
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
```

***

## 📁 Project Structure

```text
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
└─ README.md                     ← You are here
```

***

## 🚀 Getting Started

### Prerequisites

- Python 3.11+
- (Optional, later) Nmap installed on your system
- (Optional) Node.js for frontend
- (Optional) AI API key (OpenAI-compatible) for real LLM explanations

### 1. Clone the repo

```bash
git clone https://github.com/your-username/ai-web-vuln-scanner.git
cd ai-web-vuln-scanner/backend
```

### 2. Create a virtual environment

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1    # Windows PowerShell
# or
source .venv/bin/activate     # Linux / macOS
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

(or, while developing, `pip install fastapi[standard] uvicorn requests`)

### 4. Run the server

From the `backend` folder:

```bash
uvicorn app.main:app --reload
```

### 5. Open in browser

- API root: `http://127.0.0.1:8000`
- Interactive docs: `http://127.0.0.1:8000/docs`

***

## 📡 API Endpoints

| Method | Endpoint              | Description               |
|--------|-----------------------|---------------------------|
| GET    | `/health`             | Health check              |
| POST   | `/api/scan`           | Start a new scan          |
| GET    | `/api/scan/{id}`      | Get scan results by ID    |
| (plan) | `/api/report/{id}`    | Download report (JSON/PDF)|

### Example Request

```json
POST /api/scan
{
  "target_url": "https://example.com"
}
```

### Example Response (simplified)

```json
{
  "scan_id": "a1b2c3d4-...",
  "target_url": "https://example.com",
  "findings": [
    {
      "id": "f1-...",
      "type": "HEADER_MISSING",
      "endpoint": "https://example.com",
      "severity": "Medium",
      "description": "Content-Security-Policy header is missing.",
      "mitigation": "Define a Content-Security-Policy header that restricts allowed sources.",
      "ai_explanation": "The application at https://example.com is missing an important security header...",
      "ai_mitigation": "Identify which header is missing and configure it with safe defaults..."
    }
  ],
  "overall_score": 80
}
```

- If AI API is configured and online → `ai_explanation` and `ai_mitigation` can come from a real LLM.
- If offline / no key → they come from the local rule-based engine.

***

## 🔍 Vulnerabilities Detected (Current Focus)

| Vulnerability / Check | OWASP Category                   | Status   |
|-----------------------|-----------------------------------|----------|
| Missing CSP Header    | A05 – Security Misconfiguration   | Implemented via header_analyzer [owasp](https://owasp.org/www-project-secure-headers/) |
| Missing HSTS Header   | A05 – Security Misconfiguration   | Implemented via header_analyzer [owasp](https://owasp.org/www-project-secure-headers/) |
| Missing X-Frame-Options | A05 – Security Misconfiguration | Implemented via header_analyzer [owasp](https://owasp.org/www-project-secure-headers/) |
| Missing X-Content-Type-Options | A05 – Security Misconfiguration | Implemented via header_analyzer [owasp](https://owasp.org/www-project-secure-headers/) |
| Referrer-Policy       | A05 – Security Misconfiguration   | Implemented via header_analyzer [owasp](https://owasp.org/www-project-secure-headers/) |
| SQL Injection         | A03 – Injection                   | Planned  |
| Cross-Site Scripting  | A03 – Injection                   | Planned  |
| Open Ports            | A06 – Vulnerable Components       | Planned  |

***

## 🗺️ Development Roadmap

- [x] Project structure and clean FastAPI architecture
- [x] Day 0: Dev environment setup (Python, VS Code, virtualenv)
- [x] Day 1–2: Minimal FastAPI `/health` + `/api/scan` endpoints
- [x] Day 3–4: HTTP header analyzer module (security headers)
- [x] Day 5: Rule-based AI explanation engine for findings (LLM-ready)
- [ ] Day 6–7: Real LLM integration (if API key present)
- [ ] Day 8–9: Port scanner (Nmap) + basic SQLi/XSS detector
- [ ] Day 10: Report generator (JSON + PDF)
- [ ] Day 11–12: Optional React dashboard
- [ ] Day 13–14: DB integration, tests, docs, polishing

***

## ⚠️ Legal Disclaimer

> This tool is intended **for educational purposes and authorized security testing only**.  
> Do NOT scan websites without explicit permission from the owner.  
> The developer is not responsible for any misuse of this tool.

***

## 👨‍💻 Author

**Kishor A**

***

## 📄 License

MIT License — free to use, modify, and distribute with attribution.

***
