from pydantic import BaseModel, HttpUrl
from typing import List, Literal, Optional

class ScanRequest(BaseModel):
    target_url: HttpUrl

class Finding(BaseModel):
    id: str
    type: Literal["XSS", "SQLI", "HEADER_MISSING", "HEADER_WEAK"]
    endpoint: str
    description: str
    severity: Literal["Low", "Medium", "High", "Critical"]
    mitigation: str
    ai_explanation: Optional[str] = None
    ai_mitigation: Optional[str] = None

class ScanResponse(BaseModel):
    scan_id: str
    target_url: HttpUrl
    findings: List[Finding]
    overall_score: int
