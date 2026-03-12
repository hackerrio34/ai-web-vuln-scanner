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
