from fastapi import APIRouter, HTTPException
from app.schemas.scan import ScanRequest, ScanResponse
from app.services.scan_service import run_mock_scan, get_scan

router = APIRouter()

@router.post("/scan", response_model=ScanResponse)
def create_scan(request: ScanRequest) -> ScanResponse:
    """
    Start a new scan for the given target URL.
    Currently runs a mock scan with static findings.
    """
    return run_mock_scan(request)

@router.get("/scan/{scan_id}", response_model=ScanResponse)
def read_scan(scan_id: str) -> ScanResponse:
    """
    Get scan results by scan_id from in-memory store.
    """
    result = get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result
