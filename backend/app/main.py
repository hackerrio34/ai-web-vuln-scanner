from fastapi import FastAPI
from app.api.routes_scan import router as scan_router

app = FastAPI(
    title="AI Web Vulnerability Scanner",
    version="0.0.1",
    description="Minimal backend to verify environment."
)

app.include_router(scan_router, prefix="/api", tags=["scan"])

@app.get("/health")
def health_check():
    return {"status": "ok"}
