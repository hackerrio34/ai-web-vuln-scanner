import uuid
from typing import Dict, Optional
from app.schemas.scan import ScanRequest, ScanResponse, Finding
from app.scanners.header_analyzer import analyze_headers
from app.scanners.nmap_scanner import scan_ports
from app.ai_engine.explanation_generator import enrich_finding_with_ai

_scans: Dict[str, ScanResponse] = {}

def run_mock_scan(request: ScanRequest) -> ScanResponse:
    scan_id = str(uuid.uuid4())

    # Header findings from real HTTP response
    header_findings = analyze_headers(str(request.target_url))

    # Port scan findings (Nmap)
    nmap_findings = scan_ports(str(request.target_url))

    findings_with_ids: list[Finding] = []

    # Combine all raw findings
    all_raw_findings = header_findings + nmap_findings

    for f in all_raw_findings:
        base = Finding(
            id=str(uuid.uuid4()),
            type=f.type,
            endpoint=f.endpoint,
            description=f.description,
            severity=f.severity,
            mitigation=f.mitigation,
        )
        enriched = enrich_finding_with_ai(base)
        findings_with_ids.append(enriched)

    if not findings_with_ids:
        fallback = Finding(
            id=str(uuid.uuid4()),
            type="HEADER_MISSING",
            endpoint=str(request.target_url),
            description="No obvious security header or port issues detected by basic checks.",
            severity="Low",
            mitigation="Consider adding standard security headers and closing unused ports.",
        )
        fallback = enrich_finding_with_ai(fallback)
        findings_with_ids.append(fallback)

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

