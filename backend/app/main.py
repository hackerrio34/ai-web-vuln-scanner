from fastapi import FastAPI
from app.api.routes_scan import router as scan_router

app = FastAPI(
    title="AI Web Vulnerability Scanner",
    version="1.0.0",
    description=(
        "nmap-based security scanner with optional LLM-powered finding enrichment. "
        "Detects open ports, outdated services, web vulnerabilities, SSL issues, and more."
    ),
)

app.include_router(scan_router, prefix="/api", tags=["scan"])


@app.get("/health", tags=["health"])
def health_check():
    return {"status": "ok"}