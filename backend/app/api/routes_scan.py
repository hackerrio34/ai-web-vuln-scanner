from fastapi import APIRouter, HTTPException
from app.schemas.scan import ScanRequest, ScanResponse
from app.services.scan_service import run_scan, get_scan

router = APIRouter()


@router.post("/scan", response_model=ScanResponse, summary="Start a new scan")
def create_scan(request: ScanRequest) -> ScanResponse:
    """
    Launch a full nmap-based security scan against the given target.

    - **target_url**: hostname, IP address, or full URL (e.g. `https://example.com`, `192.168.1.1`)
    - **port_range**: nmap port spec (default `1-1024`; use `1-65535` for full scan)
    - **use_ai**: enrich findings with LLM explanations (requires AI config in `.env`)
    - **aggressive**: enable OS detection + vuln NSE scripts (requires root/sudo)
    """
    return run_scan(request)


@router.get("/scan/{scan_id}", response_model=ScanResponse, summary="Get scan results by ID")
def read_scan(scan_id: str) -> ScanResponse:
    """
    Retrieve a previously completed scan by its `scan_id`.
    Returns 404 if the scan ID is not found.
    """
    result = get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    return result


@router.get("/scan/{scan_id}/summary", summary="Get a plain-text summary of a scan")
def read_scan_summary(scan_id: str) -> dict:
    """
    Return just the score and summary text for a completed scan.
    Useful for quick status checks without the full findings payload.
    """
    result = get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    return {
        "scan_id":       result.scan_id,
        "target_url":    result.target_url,
        "overall_score": result.overall_score,
        "status":        result.status,
        "summary":       result.summary,
        "finding_count": len(result.findings),
    }
