from app.schemas.scan import Finding
from app.config import AI_BASE_URL, AI_API_KEY, AI_MODEL

def enrich_finding_with_ai(finding: Finding) -> Finding:
    """
    If AI config is present, this function can call a real LLM API.
    Otherwise, it falls back to local rule-based text.
    Currently we always use the local rule-based text.
    """
    explanation, mitigation = _generate_text_for_type(
        finding.type,
        finding.severity,
        finding.description,
        finding.endpoint,
    )

    finding.ai_explanation = explanation
    finding.ai_mitigation = mitigation
    return finding

def _generate_text_for_type(
    finding_type: str,
    severity: str,
    description: str,
    endpoint: str,
) -> tuple[str, str]:
    finding_type = finding_type.upper()

    if finding_type == "HEADER_MISSING":
        explanation = (
            f"The application at {endpoint} is missing an important security header. "
            f"{description} This makes it easier for attackers to abuse browser "
            f"behaviour or exploit other weaknesses, depending on which header is absent."
        )
        mitigation = (
            "Identify which header is missing (for example CSP, HSTS, X-Frame-Options, "
            "or Referrer-Policy) and configure it on the server. Start with safe, "
            "conservative values and test them in a staging environment before "
            "rolling out to production."
        )
        return explanation, mitigation

    if finding_type == "HEADER_WEAK":
        explanation = (
            f"The application at {endpoint} uses a security header with a weak value. "
            f"{description} While the header is present, its configuration does not "
            f"provide strong protection against common attacks like clickjacking."
        )
        mitigation = (
            "Review the header's current value and replace it with a recommended one. "
            "For X-Frame-Options, use 'DENY' or 'SAMEORIGIN', or enforce a strict "
            "frame-ancestors directive via Content-Security-Policy."
        )
        return explanation, mitigation

    if finding_type == "XSS":
        explanation = (
            f"The scan detected behaviour consistent with Cross-Site Scripting (XSS) "
            f"on {endpoint}. This means user-controlled input may be reflected back "
            f"into the page without proper encoding, allowing an attacker to run "
            f"malicious JavaScript in a victim's browser."
        )
        mitigation = (
            "Validate and encode all untrusted input before including it in HTML output. "
            "Avoid building HTML using string concatenation, use framework templating "
            "features, and deploy a strict Content-Security-Policy to reduce XSS impact."
        )
        return explanation, mitigation

    if finding_type == "SQLI" or finding_type == "SQL_INJECTION":
        explanation = (
            f"Potential SQL injection behaviour was observed for {endpoint}. "
            f"This suggests that user input may be concatenated directly into SQL "
            f"queries, allowing an attacker to modify the query, access other data, "
            f"or even take over the database."
        )
        mitigation = (
            "Use parameterised queries or prepared statements instead of string "
            "concatenation. Validate input on both client and server sides, and limit "
            "database permissions so the application account has only the minimum "
            "required privileges."
        )
        return explanation, mitigation

    # Fallback for unknown types
    explanation = (
        f"A security issue was detected on {endpoint}. {description} "
        f"The severity is classified as {severity}, which means it should be "
        f"reviewed and fixed according to your organisation's risk appetite."
    )
    mitigation = (
        "Review the detailed description and logs, confirm whether the behaviour "
        "is exploitable, and implement appropriate input validation, output encoding, "
        "or configuration hardening as needed."
    )
    return explanation, mitigation
