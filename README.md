# 🛡️ AI-Assisted Web Vulnerability Scanner

> An automated web security scanner powered by AI that detects vulnerabilities, explains risks in plain language, and suggests fixes — built on Python, FastAPI, and OWASP Top 10.

---

## 📌 Problem Statement

Modern web apps often contain critical security flaws like **SQL Injection**, **Cross-Site Scripting (XSS)**, and **misconfigured HTTP headers**.  
Manual security testing is slow and requires expert knowledge.  
This tool automates vulnerability detection and uses AI to make the results **easy to understand** for developers of all skill levels.

---

## 🎯 Project Objectives

- Scan any web application for common vulnerabilities
- Detect OWASP Top 10 style risks automatically
- Use AI to classify severity and explain each vulnerability
- Generate a structured penetration testing report (JSON / PDF)
- Serve as a **learning platform** for ethical hacking and secure development

---

## ⚙️ Tech Stack

| Layer       | Technology                          |
|-------------|--------------------------------------|
| Backend     | Python 3.11, FastAPI, Uvicorn        |
| Scanning    | Nmap, Requests, BeautifulSoup        |
| AI Engine   | Python LLM integration (OpenAI API) |
| Database    | PostgreSQL / MongoDB                 |
| Frontend    | React.js (optional), HTML/JS         |
| Reporting   | JSON, PDF (ReportLab / WeasyPrint)   |

---

## 🏗️ System Architecture

```
User Input (Target URL)
        │
        ▼
┌─────────────────────┐
│   Scanning Engine   │
│  ┌───────────────┐  │
│  │ Port Scanner  │  │  ← Nmap
│  │ Header Check  │  │  ← Requests / httpx
│  │ Vuln Detector │  │  ← SQLi / XSS payloads
│  └───────────────┘  │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Result Processor   │  ← Normalizes all findings
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  AI Analysis Engine │
│  ┌───────────────┐  │
│  │ Risk Classify │  │  ← Critical / High / Medium / Low
│  │ Explanation   │  │  ← Plain English description
│  │ Mitigation    │  │  ← Step-by-step fix suggestions
│  └───────────────┘  │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Report Generator   │  ← JSON / PDF export
└────────┬────────────┘
         │
         ▼
   Dashboard / Output
```

---

## 📁 Project Structure

```
ai-web-vuln-scanner/
├─ backend/
│  ├─ app/
│  │  ├─ main.py                 # FastAPI app entry point
│  │  ├─ api/
│  │  │  └─ routes_scan.py       # /scan endpoints
│  │  ├─ schemas/
│  │  │  └─ scan.py              # Pydantic request/response models
│  │  ├─ services/
│  │  │  └─ scan_service.py      # Core scan logic
│  │  ├─ scanners/
│  │  │  ├─ nmap_scanner.py      # Port scanning
│  │  │  ├─ header_analyzer.py   # HTTP security headers
│  │  │  └─ vuln_detector.py     # SQLi / XSS detection
│  │  ├─ ai_engine/
│  │  │  ├─ severity_classifier.py
│  │  │  └─ explanation_generator.py
│  │  └─ db/
│  │     └─ database.py
│  ├─ requirements.txt
│  └─ README.md
├─ frontend/                     # Optional React dashboard
├─ docs/
│  ├─ architecture.md
│  └─ sample-report.json
└─ README.md                     ← You are here
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.11+
- Nmap installed on your system
- (Optional) Node.js for frontend

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
source .venv/bin/activate       # Linux / macOS
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the server
```bash
uvicorn app.main:app --reload
```

### 5. Open in browser
- API: http://127.0.0.1:8000
- Interactive Docs: http://127.0.0.1:8000/docs

---

## 📡 API Endpoints

| Method | Endpoint          | Description               |
|--------|-------------------|---------------------------|
| POST   | `/api/scan`       | Start a new scan          |
| GET    | `/api/scan/{id}`  | Get scan results by ID    |
| GET    | `/api/report/{id}`| Download report (JSON/PDF)|

### Example Request
```json
POST /api/scan
{
  "target_url": "https://example.com"
}
```

### Example Response
```json
{
  "scan_id": "a1b2c3d4-...",
  "target_url": "https://example.com",
  "findings": [
    {
      "type": "XSS",
      "endpoint": "https://example.com?q=<script>",
      "severity": "High",
      "description": "Possible reflected XSS in query parameter 'q'.",
      "mitigation": "Encode output, validate input, implement Content-Security-Policy."
    },
    {
      "type": "HEADER_MISSING",
      "endpoint": "https://example.com",
      "severity": "Medium",
      "description": "Strict-Transport-Security header is missing.",
      "mitigation": "Add HSTS header with max-age and includeSubDomains."
    }
  ],
  "overall_score": 65
}
```

---

## 🔍 Vulnerabilities Detected

| Vulnerability         | OWASP Category               | Severity |
|-----------------------|------------------------------|----------|
| SQL Injection         | A03 – Injection              | Critical |
| Cross-Site Scripting  | A03 – Injection              | High     |
| Missing HSTS Header   | A05 – Security Misconfiguration | Medium |
| Missing CSP Header    | A05 – Security Misconfiguration | Medium |
| Open Ports            | A06 – Vulnerable Components  | Varies   |

---

## 🗺️ Development Roadmap

- [x] Project structure and clean architecture setup
- [ ] Day 0: Dev environment setup (Python, VS Code, virtualenv)
- [ ] Day 1–2: Minimal FastAPI `/health` + `/scan` endpoints
- [ ] Day 3–4: Port scanner + header analyzer modules
- [ ] Day 5–6: SQLi and XSS vulnerability detector
- [ ] Day 7–8: AI explanation and severity classification engine
- [ ] Day 9: Report generator (JSON + PDF)
- [ ] Day 10–11: Optional React dashboard
- [ ] Day 12–14: Tests, docs, polishing

---

## ⚠️ Legal Disclaimer

> This tool is intended **for educational purposes and authorized security testing only**.  
> Do NOT scan websites without explicit permission from the owner.  
> The developers are not responsible for any misuse of this tool.

---

## 👨‍💻 Author
Kishor A

---

## 📄 License

MIT License — free to use, modify, and distribute with attribution.
