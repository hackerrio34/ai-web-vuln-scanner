"""
vuln_detector.py
----------------
Runs nmap NSE web-application scripts against HTTP/HTTPS ports
to detect SQLi, XSS, CSRF, open redirects, exposed files, etc.

This is separate from nmap_scanner.py which covers port/service level.
Here we focus purely on web-layer vulnerabilities.

Requires nmap with NSE scripts available (standard nmap install).
Some scripts (http-sql-injection) can be slow – increase timeout if needed.
"""

from __future__ import annotations

import re
from typing import List
from urllib.parse import urlparse

import nmap

from app.schemas.scan import Finding


# NSE scripts targeted at web-layer vulnerabilities
_WEB_NSE_SCRIPTS = ",".join([
    "http-sql-injection",
    "http-stored-xss",
    "http-dombased-xss",
    "http-phpself-xss",
    "http-xssed",
    "http-csrf",
    "http-open-redirect",
    "http-shellshock",
    "http-trace",
    "http-put",
    "http-methods",
    "http-git",
    "http-config-backup",
    "http-backup-finder",
    "http-auth-finder",
    "http-default-accounts",
    "http-wordpress-users",
    "http-headers",
    "http-security-headers",
])

# script_name_pattern → (finding_type, description, severity, mitigation)
_SCRIPT_RULES: List[tuple[re.Pattern, str, str, str, str]] = [
    (
        re.compile(r"http-sql-injection", re.I),
        "SQLI",
        "Potential SQL injection point detected by NSE http-sql-injection script.",
        "Critical",
        (
            "Use parameterised queries or prepared statements throughout the codebase. "
            "Never concatenate user input directly into SQL strings. "
            "Apply least-privilege database accounts."
        ),
    ),
    (
        re.compile(r"http-stored-xss|http-dombased-xss|http-phpself-xss|http-xssed", re.I),
        "XSS",
        "Potential Cross-Site Scripting (XSS) vulnerability detected by NSE.",
        "High",
        (
            "HTML-encode all user-controlled output before rendering. "
            "Use a strict Content-Security-Policy header. "
            "Prefer framework templating engines over manual string building."
        ),
    ),
    (
        re.compile(r"http-csrf", re.I),
        "MISC",
        "Potential Cross-Site Request Forgery (CSRF) weakness detected.",
        "Medium",
        (
            "Implement CSRF tokens on all state-changing forms and API endpoints. "
            "Validate the Origin/Referer header on sensitive requests. "
            "Use SameSite=Strict or SameSite=Lax cookie attributes."
        ),
    ),
    (
        re.compile(r"http-open-redirect", re.I),
        "MISC",
        "Open redirect vulnerability detected – attackers can redirect users to malicious sites.",
        "Medium",
        (
            "Validate redirect targets against an allowlist of trusted domains. "
            "Never use raw user input as a redirect destination."
        ),
    ),
    (
        re.compile(r"http-shellshock", re.I),
        "MISC",
        "Shellshock (CVE-2014-6271) vulnerability detected in CGI endpoint.",
        "Critical",
        (
            "Update bash to a patched version immediately. "
            "Audit and remove unnecessary CGI scripts."
        ),
    ),
    (
        re.compile(r"http-trace", re.I),
        "MISC",
        "HTTP TRACE method is enabled – exposes session tokens via cross-site tracing (XST).",
        "Medium",
        "Disable TRACE in the web server config (e.g. TraceEnable Off in Apache).",
    ),
    (
        re.compile(r"http-put", re.I),
        "MISC",
        "HTTP PUT method is enabled – arbitrary file upload may be possible.",
        "High",
        "Disable the PUT method unless explicitly required by the application design.",
    ),
    (
        re.compile(r"http-git", re.I),
        "MISC",
        "Exposed .git directory detected – source code and credentials may be accessible.",
        "Critical",
        (
            "Immediately block public access to .git at the web server level. "
            "Rotate any secrets that may have been committed to the repository."
        ),
    ),
    (
        re.compile(r"http-config-backup|http-backup-finder", re.I),
        "MISC",
        "Backup or configuration file found in a publicly accessible location.",
        "High",
        (
            "Remove backup files from the web root. "
            "Add rules to block access to common backup extensions (*.bak, *.old, *.swp)."
        ),
    ),
    (
        re.compile(r"http-default-accounts", re.I),
        "DEFAULT_CREDENTIALS",
        "Default credentials accepted by web application or admin panel.",
        "Critical",
        (
            "Change all default credentials immediately. "
            "Enforce a strong password policy and enable MFA on admin interfaces."
        ),
    ),
    (
        re.compile(r"http-wordpress-users", re.I),
        "MISC",
        "WordPress user enumeration is possible – usernames can be harvested for brute-force.",
        "Medium",
        (
            "Disable the WordPress REST API user endpoint if not needed. "
            "Use a security plugin to block username enumeration."
        ),
    ),
    (
        re.compile(r"http-security-headers|http-headers", re.I),
        "HEADER_MISSING",
        "Web server response is missing recommended security headers.",
        "Medium",
        (
            "Add Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, "
            "X-Content-Type-Options, and Referrer-Policy to all HTTP responses."
        ),
    ),
]


# ── Public API ─────────────────────────────────────────────────────────────────

def scan_web_vulns(
    target: str,
    port_range: str = "80,443,8080,8443",
) -> List[Finding]:
    """
    Run NSE web-vuln scripts against HTTP/HTTPS ports on *target*.

    Parameters
    ----------
    target      : hostname, IP, or full URL
    port_range  : ports to probe, defaults to common web ports
    """
    host = _extract_host(target)
    nm   = nmap.PortScanner()
    args = f"-p {port_range} --open -sV --script={_WEB_NSE_SCRIPTS}"

    try:
        nm.scan(hosts=host, arguments=args)
    except nmap.PortScannerError as exc:
        return [_error_finding(host, str(exc))]
    except Exception as exc:
        return [_error_finding(host, str(exc))]

    findings: List[Finding] = []

    for scanned_host in nm.all_hosts():
        info = nm[scanned_host]
        if info.state() != "up":
            continue

        for proto in info.all_protocols():
            for port, pdata in sorted(info[proto].items()):
                if pdata.get("state") != "open":
                    continue

                endpoint = f"{scanned_host}:{port}"
                scripts  = pdata.get("script", {})

                for script_name, output in scripts.items():
                    finding = _match_script(endpoint, script_name, output)
                    if finding:
                        findings.append(finding)

    return findings


# ── Helpers ────────────────────────────────────────────────────────────────────

def _extract_host(target: str) -> str:
    if "://" in target:
        return urlparse(target).hostname or target
    return target


def _match_script(
    endpoint: str, script_name: str, output: str
) -> Finding | None:
    """Return a Finding if the script output matches a known rule, else None."""
    for name_pat, ftype, description, severity, mitigation in _SCRIPT_RULES:
        if name_pat.search(script_name):
            # Only create a finding if the output is non-trivial
            if output.strip() and "ERROR" not in output.upper()[:20]:
                return Finding(
                    id="",
                    type=ftype,
                    endpoint=endpoint,
                    description=f"[{script_name}] {description}",
                    severity=severity,
                    mitigation=mitigation,
                    raw_nmap_output=output[:600],
                )
    return None


def _error_finding(host: str, msg: str) -> Finding:
    return Finding(
        id="",
        type="MISC",
        endpoint=host,
        description=f"Web vuln scan failed: {msg}",
        severity="Info",
        mitigation=(
            "Ensure nmap is installed with NSE scripts available. "
            "Run 'nmap --script-updatedb' if scripts are missing."
        ),
    )