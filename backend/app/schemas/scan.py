from pydantic import BaseModel
from typing import List, Literal, Optional

# ── Finding types ──────────────────────────────────────────────────────────────
FindingType = Literal[
    "OPEN_PORT",
    "WEAK_SERVICE",
    "OUTDATED_SERVICE",
    "OS_DETECTED",
    "XSS",
    "SQLI",
    "HEADER_MISSING",
    "HEADER_WEAK",
    "SSL_ISSUE",
    "DEFAULT_CREDENTIALS",
    "ANONYMOUS_ACCESS",
    "MISC",
]

SeverityLevel = Literal["Info", "Low", "Medium", "High", "Critical"]


class Finding(BaseModel):
    id: str
    type: FindingType
    endpoint: str
    description: str
    severity: SeverityLevel
    mitigation: str
    cve_references: Optional[List[str]] = None
    raw_nmap_output: Optional[str] = None
    ai_explanation: Optional[str] = None
    ai_mitigation: Optional[str] = None


class ScanRequest(BaseModel):
    target_url: str          # accepts IPs, hostnames, and full URLs
    port_range: str = "1-1024"
    use_ai: bool = False     # True → enrich findings with LLM
    aggressive: bool = False # True → OS detection + vuln NSE scripts (needs root)


class ScanResponse(BaseModel):
    scan_id: str
    target_url: str
    status: Literal["complete", "error"] = "complete"
    findings: List[Finding]
    overall_score: int       # 0–100, higher = more secure
    summary: Optional[str] = None
    error: Optional[str] = None