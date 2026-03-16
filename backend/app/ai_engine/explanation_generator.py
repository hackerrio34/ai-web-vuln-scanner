"""
explanation_generator.py
------------------------
Enriches Findings with human-readable AI explanations and mitigations.

Two modes:
  use_ai=False  → fast, offline, rule-based text (always works)
  use_ai=True   → calls the configured LLM API (requires AI_API_KEY in .env)

The LLM path falls back to rule-based if the API call fails, so the
scanner always returns enriched findings regardless of AI availability.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

import httpx

from app.config import AI_BASE_URL, AI_API_KEY, AI_MODEL
from app.schemas.scan import Finding

logger = logging.getLogger(__name__)


# ── Public entry point ─────────────────────────────────────────────────────────

def enrich_finding(finding: Finding, use_ai: bool = False) -> Finding:
    """
    Attach ai_explanation and ai_mitigation to *finding*.
    If use_ai is True and AI config is present, calls the LLM.
    Otherwise uses rule-based text.
    """
    if use_ai and AI_API_KEY and AI_BASE_URL and AI_MODEL:
        try:
            explanation, mitigation = _llm_enrich(finding)
            finding.ai_explanation = explanation
            finding.ai_mitigation  = mitigation
            return finding
        except Exception as exc:
            logger.warning("LLM enrichment failed (%s) – falling back to rule-based.", exc)

    # Rule-based (default / fallback)
    explanation, mitigation = _rule_based_enrich(finding)
    finding.ai_explanation = explanation
    finding.ai_mitigation  = mitigation
    return finding


# ── LLM path ──────────────────────────────────────────────────────────────────

def _llm_enrich(finding: Finding) -> tuple[str, str]:
    """
    Call the configured LLM and ask it to explain the finding in plain English
    and suggest a concrete mitigation. Returns (explanation, mitigation).

    Expects the model to reply with a JSON object:
      { "explanation": "...", "mitigation": "..." }
    """
    prompt = _build_prompt(finding)

    payload = {
        "model": AI_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        "max_tokens": 512,
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {AI_API_KEY}",
    }

    with httpx.Client(timeout=30) as client:
        response = client.post(
            f"{AI_BASE_URL.rstrip('/')}/chat/completions",
            json=payload,
            headers=headers,
        )
        response.raise_for_status()

    raw = response.json()
    content = raw["choices"][0]["message"]["content"].strip()

    # Strip markdown fences if the model wrapped the JSON
    if content.startswith("```"):
        content = content.split("```")[1]
        if content.startswith("json"):
            content = content[4:]
    content = content.strip()

    parsed = json.loads(content)
    return parsed["explanation"], parsed["mitigation"]


def _build_prompt(finding: Finding) -> str:
    return f"""You are a cybersecurity expert writing a concise vulnerability report entry.

Given the following security finding from an automated nmap scan, provide:
1. A plain-English explanation of what the finding means and why it is a risk.
2. A concrete, actionable mitigation step (2-4 sentences).

Finding details:
  Type        : {finding.type}
  Endpoint    : {finding.endpoint}
  Description : {finding.description}
  Severity    : {finding.severity}

Respond ONLY with a JSON object in this exact format (no markdown, no extra text):
{{
  "explanation": "<plain-english explanation, 3-5 sentences>",
  "mitigation": "<concrete mitigation, 2-4 sentences>"
}}"""


# ── Rule-based path ────────────────────────────────────────────────────────────

def _rule_based_enrich(finding: Finding) -> tuple[str, str]:
    ftype = finding.type.upper()

    handlers = {
        "OPEN_PORT":           _text_open_port,
        "OUTDATED_SERVICE":    _text_outdated_service,
        "OS_DETECTED":         _text_os_detected,
        "SSL_ISSUE":           _text_ssl_issue,
        "ANONYMOUS_ACCESS":    _text_anonymous_access,
        "DEFAULT_CREDENTIALS": _text_default_credentials,
        "HEADER_MISSING":      _text_header_missing,
        "HEADER_WEAK":         _text_header_weak,
        "XSS":                 _text_xss,
        "SQLI":                _text_sqli,
        "MISC":                _text_misc,
    }

    handler = handlers.get(ftype, _text_misc)
    return handler(finding)


# ── Per-type text generators ───────────────────────────────────────────────────

def _text_open_port(f: Finding) -> tuple[str, str]:
    explanation = (
        f"The scan found an open port at {f.endpoint}. "
        f"{f.description} "
        "Every open port is a potential entry point for attackers. "
        "If the service is unnecessary or improperly secured, it significantly "
        "increases the attack surface of the system."
    )
    mitigation = (
        "Verify that the service running on this port is required for business operations. "
        "If it is not needed, stop the service and block the port at the firewall. "
        "If the service is required, ensure it is running the latest patched version "
        "and restrict access to trusted IP addresses only."
    )
    return explanation, mitigation


def _text_outdated_service(f: Finding) -> tuple[str, str]:
    explanation = (
        f"An outdated or end-of-life service version was identified at {f.endpoint}. "
        f"{f.description} "
        "Older software versions frequently contain known, publicly disclosed "
        "vulnerabilities that attackers can exploit with off-the-shelf tools."
    )
    mitigation = (
        "Update the affected service to the latest stable release immediately. "
        "Subscribe to the vendor's security advisories so future patches are applied promptly. "
        "After updating, re-scan to confirm the issue is resolved."
    )
    return explanation, mitigation


def _text_os_detected(f: Finding) -> tuple[str, str]:
    explanation = (
        f"The operating system of {f.endpoint} was identified through TCP/IP fingerprinting. "
        f"{f.description} "
        "Knowing the exact OS and version allows an attacker to narrow down which "
        "exploits and privilege-escalation techniques are most likely to succeed."
    )
    mitigation = (
        "Harden the TCP/IP stack to reduce fingerprinting accuracy "
        "(e.g. adjust TTL values and TCP window sizes). "
        "Keep the OS fully patched regardless of fingerprinting hardening. "
        "Deploy a host-based firewall and intrusion detection system."
    )
    return explanation, mitigation


def _text_ssl_issue(f: Finding) -> tuple[str, str]:
    explanation = (
        f"An SSL/TLS configuration issue was found at {f.endpoint}. "
        f"{f.description} "
        "Weak or misconfigured TLS allows attackers to intercept encrypted traffic "
        "(man-in-the-middle), read sensitive data, or impersonate the server."
    )
    mitigation = (
        "Disable all deprecated protocol versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1) "
        "and only allow TLS 1.2 and TLS 1.3. "
        "Ensure the certificate is signed by a trusted CA and is not expired. "
        "Use tools like testssl.sh or SSL Labs to verify the final configuration."
    )
    return explanation, mitigation


def _text_anonymous_access(f: Finding) -> tuple[str, str]:
    explanation = (
        f"Anonymous access is enabled on {f.endpoint}. "
        f"{f.description} "
        "This allows any unauthenticated user to connect and potentially read, "
        "write, or execute files depending on the service's configuration."
    )
    mitigation = (
        "Disable anonymous login in the service configuration file. "
        "Enforce authentication for all connections. "
        "If anonymous read-only access is genuinely required, "
        "ensure write permissions are strictly disabled and monitor access logs."
    )
    return explanation, mitigation


def _text_default_credentials(f: Finding) -> tuple[str, str]:
    explanation = (
        f"The service at {f.endpoint} appears to accept default credentials. "
        f"{f.description} "
        "Default credentials are the first thing attackers try and are trivially "
        "exploitable, often leading to full administrative access within seconds."
    )
    mitigation = (
        "Change all default usernames and passwords immediately. "
        "Enforce a strong password policy across all services and admin panels. "
        "Enable multi-factor authentication where the service supports it. "
        "Audit all admin accounts and remove any that are unused."
    )
    return explanation, mitigation


def _text_header_missing(f: Finding) -> tuple[str, str]:
    explanation = (
        f"A required security header is missing from the HTTP responses at {f.endpoint}. "
        f"{f.description} "
        "Security headers instruct the browser how to handle the page content, "
        "and their absence leaves users exposed to attacks like clickjacking, "
        "MIME sniffing, and information leakage."
    )
    mitigation = (
        "Add the missing header to your web server or application middleware. "
        "Start with conservative values and test in a staging environment first. "
        "Use securityheaders.com to verify your header configuration after deployment."
    )
    return explanation, mitigation


def _text_header_weak(f: Finding) -> tuple[str, str]:
    explanation = (
        f"A security header at {f.endpoint} is present but configured with a weak value. "
        f"{f.description} "
        "A poorly configured header may provide a false sense of security "
        "while still allowing attacks it is intended to prevent."
    )
    mitigation = (
        "Review the header's current value and replace it with the recommended configuration. "
        "Consult the MDN Web Docs or OWASP Secure Headers Project for guidance on "
        "strong values for each header type."
    )
    return explanation, mitigation


def _text_xss(f: Finding) -> tuple[str, str]:
    explanation = (
        f"A potential Cross-Site Scripting (XSS) vulnerability was identified at {f.endpoint}. "
        f"{f.description} "
        "XSS allows attackers to inject malicious JavaScript into pages viewed by other users, "
        "enabling session hijacking, credential theft, and phishing attacks."
    )
    mitigation = (
        "HTML-encode all user-controlled values before rendering them in the page. "
        "Avoid building HTML through string concatenation; use framework templating features. "
        "Deploy a strict Content-Security-Policy to limit the damage if XSS occurs. "
        "Perform thorough manual and automated testing of all input fields."
    )
    return explanation, mitigation


def _text_sqli(f: Finding) -> tuple[str, str]:
    explanation = (
        f"A potential SQL injection vulnerability was identified at {f.endpoint}. "
        f"{f.description} "
        "SQL injection allows attackers to manipulate database queries, "
        "potentially reading, modifying, or deleting all data, "
        "and in some cases executing OS commands on the database server."
    )
    mitigation = (
        "Replace all string-concatenated SQL queries with parameterised queries "
        "or prepared statements. "
        "Apply input validation on both client and server sides. "
        "Limit database account permissions to the minimum required by the application. "
        "Enable query logging to detect exploitation attempts."
    )
    return explanation, mitigation


def _text_misc(f: Finding) -> tuple[str, str]:
    explanation = (
        f"A security issue was detected at {f.endpoint}. "
        f"{f.description} "
        f"This finding has a severity rating of '{f.severity}' and should be "
        "reviewed and remediated according to your organisation's risk appetite."
    )
    mitigation = (
        "Review the raw scanner output and the full description of this finding. "
        "Confirm whether the behaviour is exploitable in your environment, "
        "then apply appropriate hardening such as input validation, "
        "access control enforcement, or configuration changes."
    )
    return explanation, mitigation