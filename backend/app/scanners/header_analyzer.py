from typing import List, Literal
from urllib.parse import urlparse

import requests
from app.schemas.scan import Finding

SecurityHeaderType = Literal[
    "HEADER_MISSING",
    "HEADER_WEAK"
]

REQUIRED_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


def analyze_headers(target_url: str) -> List[Finding]:
    findings: List[Finding] = []

    try:
        response = requests.get(target_url, timeout=5, allow_redirects=True)
    except Exception as exc:
        # If the site is unreachable, just return no header findings for now
        return findings

    headers = response.headers
    parsed = urlparse(target_url)
    endpoint = f"{parsed.scheme}://{parsed.netloc}"

    # Check for missing important security headers
    for header_name in REQUIRED_HEADERS:
        if header_name not in headers:
            findings.append(
                Finding(
                    id="",
                    type="HEADER_MISSING",
                    endpoint=endpoint,
                    description=f"{header_name} header is missing.",
                    severity=_severity_for_missing_header(header_name),
                    mitigation=_mitigation_for_header(header_name),
                )
            )

    # Basic weak-value checks (example for X-Frame-Options)
    xfo = headers.get("X-Frame-Options")
    if xfo and xfo.lower() not in {"deny", "sameorigin"}:
        findings.append(
            Finding(
                id="",
                type="HEADER_WEAK",
                endpoint=endpoint,
                description=(
                    f"X-Frame-Options is set to '{xfo}', which may be unsafe. "
                    "Recommended values are 'DENY' or 'SAMEORIGIN'."
                ),
                severity="Low",
                mitigation=(
                    "Change X-Frame-Options to 'DENY' or 'SAMEORIGIN', or use "
                    "a Content-Security-Policy with a strict frame-ancestors directive."
                ),
            )
        )

    return findings


def _severity_for_missing_header(header_name: str) -> str:
    if header_name in {"Content-Security-Policy", "Strict-Transport-Security"}:
        return "Medium"
    if header_name in {"X-Frame-Options", "X-Content-Type-Options"}:
        return "Medium"
    return "Low"


def _mitigation_for_header(header_name: str) -> str:
    if header_name == "Strict-Transport-Security":
        return (
            "Enable HSTS by adding the Strict-Transport-Security header with an "
            "appropriate max-age and includeSubDomains on HTTPS responses."
        )
    if header_name == "Content-Security-Policy":
        return (
            "Define a Content-Security-Policy header that restricts allowed script, "
            "style, image, and frame sources to trusted origins."
        )
    if header_name == "X-Frame-Options":
        return (
            "Add the X-Frame-Options header with value 'DENY' or 'SAMEORIGIN', "
            "or use CSP frame-ancestors to prevent clickjacking."
        )
    if header_name == "X-Content-Type-Options":
        return (
            "Add the X-Content-Type-Options header with value 'nosniff' to prevent "
            "browsers from MIME-sniffing the response."
        )
    if header_name == "Referrer-Policy":
        return (
            "Add a Referrer-Policy header, for example 'strict-origin-when-cross-origin', "
            "to limit sensitive referrer information leakage."
        )
    return "Review security best practices for this header and configure it safely."
