"""
scan_service.py
---------------
Orchestrates all scanners and builds the final ScanResponse.

Flow:
  1. Port + service scan      (nmap_scanner)
  2. Web vuln scan            (vuln_detector)  ← only if web ports found or target is a URL
  3. AI / rule-based enrichment per finding   (explanation_generator)
  4. Score calculation + summary
"""

from __future__ import annotations

import uuid
from typing import Dict, Optional
from urllib.parse import urlparse

from app.schemas.scan import ScanRequest, ScanResponse, Finding
from app.scanners.nmap_scanner import scan_ports
from app.scanners.vuln_detector import scan_web_vulns
from app.ai_engine.explanation_generator import enrich_finding

# In-memory store: scan_id → ScanResponse
_store: Dict[str, ScanResponse] = {}


# ── Public API ─────────────────────────────────────────────────────────────────

def run_scan(request: ScanRequest) -> ScanResponse:
    scan_id = str(uuid.uuid4())
    target  = request.target_url

    try:
        # ── Step 1: Port / service scan ────────────────────────────────────────
        port_findings = scan_ports(
            target=target,
            port_range=request.port_range,
            aggressive=request.aggressive,
        )

        # ── Step 2: Web vuln scan (always run against common web ports) ────────
        web_findings = scan_web_vulns(
            target=target,
            port_range=_web_ports_for(target),
        )

        all_raw = port_findings + web_findings

        # ── Step 3: Assign IDs + enrich ────────────────────────────────────────
        enriched: list[Finding] = []
        for f in all_raw:
            f.id = str(uuid.uuid4())
            enriched.append(enrich_finding(f, use_ai=request.use_ai))

        # ── Step 4: Fallback if nothing found ──────────────────────────────────
        if not enriched:
            fallback = Finding(
                id=str(uuid.uuid4()),
                type="MISC",
                endpoint=target,
                description=(
                    "No open ports or web vulnerabilities were detected in the scanned range. "
                    "This may indicate a well-hardened host, a firewall blocking probes, "
                    "or the target being offline."
                ),
                severity="Info",
                mitigation=(
                    "Confirm the target is reachable and consider scanning a wider port range. "
                    "Use aggressive mode for deeper OS and service analysis."
                ),
            )
            fallback = enrich_finding(fallback, use_ai=request.use_ai)
            enriched.append(fallback)

        score   = _compute_score(enriched)
        summary = _build_summary(enriched, score)

        response = ScanResponse(
            scan_id=scan_id,
            target_url=target,
            status="complete",
            findings=enriched,
            overall_score=score,
            summary=summary,
        )

    except Exception as exc:
        response = ScanResponse(
            scan_id=scan_id,
            target_url=target,
            status="error",
            findings=[],
            overall_score=0,
            error=str(exc),
        )

    _store[scan_id] = response
    return response


def get_scan(scan_id: str) -> Optional[ScanResponse]:
    return _store.get(scan_id)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _web_ports_for(target: str) -> str:
    """
    If the target URL specifies a port, probe only that port for web vulns.
    Otherwise use the standard web port list.
    """
    if "://" in target:
        parsed = urlparse(target)
        if parsed.port:
            return str(parsed.port)
        scheme = parsed.scheme.lower()
        return "443" if scheme == "https" else "80"
    return "80,443,8080,8443"


def _compute_score(findings: list[Finding]) -> int:
    """
    Score starts at 100. Deductions per finding:
      Critical → -30    High → -15    Medium → -8    Low → -3    Info → 0
    """
    deductions = {"Critical": 30, "High": 15, "Medium": 8, "Low": 3, "Info": 0}
    score = 100
    for f in findings:
        score -= deductions.get(f.severity, 0)
    return max(score, 0)


def _build_summary(findings: list[Finding], score: int) -> str:
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    parts = [f"Overall security score: {score}/100."]
    for severity in ("Critical", "High", "Medium", "Low", "Info"):
        n = counts.get(severity, 0)
        if n:
            parts.append(f"{n} {severity} finding{'s' if n > 1 else ''}.")

    if score >= 80:
        parts.append("The target appears reasonably secure. Address any High/Critical findings promptly.")
    elif score >= 50:
        parts.append("Several issues require attention. Prioritise Critical and High findings.")
    else:
        parts.append("Significant security issues detected. Immediate remediation is recommended.")

    return " ".join(parts)