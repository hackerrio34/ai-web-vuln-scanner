import uuid
from typing import Dict, Optional
from app.schemas.scan import ScanRequest, ScanResponse, Finding
from app.scanners.header_analyzer import analyze_headers

_scans: Dict[str, ScanResponse] = {}

def run_mock_scan(request: ScanRequest) -> ScanResponse:
    scan_id = str(uuid.uuid4())

    # Header findings from real HTTP response
    header_findings = analyze_headers(str(request.target_url))

    # Give each finding a unique id
    findings_with_ids = []
    for f in header_findings:
        findings_with_ids.append(
            Finding(
                id=str(uuid.uuid4()),
                type=f.type,
                endpoint=f.endpoint,
                description=f.description,
                severity=f.severity,
                mitigation=f.mitigation,
            )
        )

    # If no findings, keep at least one example for now
    if not findings_with_ids:
        findings_with_ids.append(
            Finding(
                id=str(uuid.uuid4()),
                type="HEADER_MISSING",
                endpoint=str(request.target_url),
                description="No obvious security header issues detected by basic checks.",
                severity="Low",
                mitigation="Consider adding standard security headers such as CSP, HSTS, X-Frame-Options and Referrer-Policy.",
            )
        )

    response = ScanResponse(
        scan_id=scan_id,
        target_url=request.target_url,
        findings=findings_with_ids,
        overall_score=_compute_score(findings_with_ids),
    )

    _scans[scan_id] = response
    return response

def get_scan(scan_id: str) -> Optional[ScanResponse]:
    return _scans.get(scan_id)

def _compute_score(findings: list[Finding]) -> int:
    # Simple scoring: start at 100 and subtract points per severity
    score = 100
    for f in findings:
        if f.severity == "Critical":
            score -= 30
        elif f.severity == "High":
            score -= 20
        elif f.severity == "Medium":
            score -= 10
        elif f.severity == "Low":
            score -= 5
    return max(score, 0)

