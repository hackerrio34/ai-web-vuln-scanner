"""
nmap_scanner.py
---------------
Core port + service scanner using python-nmap.

Two scan modes:
  Normal     : -sV -sC --open  → open ports, service versions, default safe scripts
  Aggressive : -A --open + vuln/web NSE scripts → adds OS detection, deeper checks

Findings produced:
  OPEN_PORT        - every open port with risk context
  OUTDATED_SERVICE - version string matches known weak/EOL patterns
  OS_DETECTED      - OS fingerprint result (Info severity)
  SSL_ISSUE        - expired cert, weak protocol, self-signed
  ANONYMOUS_ACCESS - anonymous FTP allowed
  DEFAULT_CREDENTIALS - service may accept default creds (NSE result)
  MISC             - any other NSE VULNERABLE hit
"""

from __future__ import annotations

import re
from typing import List, Dict, Any
from urllib.parse import urlparse

import nmap

from app.schemas.scan import Finding


# ── Risk catalogue: port → (severity, context_note) ───────────────────────────
_PORT_RISK: Dict[int, tuple[str, str]] = {
    21:    ("High",     "FTP – plaintext, prone to anonymous access and brute-force."),
    22:    ("Medium",   "SSH – ensure key-only auth and disable root login."),
    23:    ("Critical", "Telnet – plaintext protocol, must be replaced with SSH."),
    25:    ("High",     "SMTP – can be abused for open relay if misconfigured."),
    53:    ("Medium",   "DNS – verify zone-transfer and recursion restrictions."),
    80:    ("Medium",   "HTTP – all traffic is plaintext; consider forcing HTTPS."),
    110:   ("High",     "POP3 – plaintext email retrieval."),
    111:   ("High",     "RPC portmapper – frequently exploited on Linux systems."),
    135:   ("High",     "MSRPC – common Windows lateral-movement attack surface."),
    139:   ("High",     "NetBIOS – legacy Windows file sharing, often targeted."),
    143:   ("High",     "IMAP – plaintext email; use IMAPS (993) instead."),
    443:   ("Info",     "HTTPS – verify certificate validity and TLS configuration."),
    445:   ("Critical", "SMB – primary ransomware / EternalBlue vector."),
    512:   ("Critical", "rexec – unauthenticated remote execution risk."),
    513:   ("Critical", "rlogin – legacy trust-based login with no encryption."),
    514:   ("Critical", "rsh – no authentication whatsoever."),
    1433:  ("High",     "MSSQL – database port, restrict to app-tier only."),
    1521:  ("High",     "Oracle DB – database port, restrict to app-tier only."),
    2049:  ("High",     "NFS – verify export restrictions carefully."),
    3306:  ("High",     "MySQL – database port, never expose to the internet."),
    3389:  ("High",     "RDP – brute-force target; enable NLA and MFA."),
    4444:  ("Critical", "Common backdoor / default Metasploit listener port."),
    5432:  ("High",     "PostgreSQL – database port, restrict to app-tier only."),
    5900:  ("High",     "VNC – often uses weak or no authentication."),
    6379:  ("High",     "Redis – unauthenticated by default in many deployments."),
    8080:  ("Medium",   "HTTP alternate – may expose admin panels or dev servers."),
    8443:  ("Medium",   "HTTPS alternate – verify same hardening as port 443."),
    27017: ("High",     "MongoDB – unauthenticated by default in older versions."),
}

_DEFAULT_PORT_SEVERITY = "Low"
_DEFAULT_PORT_NOTE = "Verify that this service is intentionally exposed."


# ── Weak / outdated service version patterns ───────────────────────────────────
# Each entry: (compiled_regex, description, mitigation)
_WEAK_SERVICE_PATTERNS: List[tuple[re.Pattern, str, str]] = [
    (
        re.compile(r"OpenSSH\s+[1-6]\.", re.I),
        "Outdated OpenSSH version detected.",
        "Upgrade to the latest stable OpenSSH release.",
    ),
    (
        re.compile(r"Apache(?:/| )(1\.|2\.[0-3]\.)", re.I),
        "Outdated Apache httpd version detected.",
        "Upgrade Apache to the latest 2.4.x release and apply all patches.",
    ),
    (
        re.compile(r"nginx/0\.|nginx/1\.[0-9]\b", re.I),
        "Potentially outdated nginx version detected.",
        "Upgrade nginx to the latest stable release.",
    ),
    (
        re.compile(r"vsftpd\s+2\.[0-2]", re.I),
        "Outdated vsftpd – CVE-2011-2523 backdoor risk present in 2.3.4.",
        "Upgrade vsftpd to 3.x and disable anonymous login.",
    ),
    (
        re.compile(r"ProFTPD\s+1\.[0-3]\.", re.I),
        "Outdated ProFTPD version detected.",
        "Upgrade ProFTPD to the latest stable release.",
    ),
    (
        re.compile(r"Microsoft-IIS/[1-7]\.", re.I),
        "Outdated Microsoft IIS version detected.",
        "Upgrade IIS and apply all current Windows security patches.",
    ),
    (
        re.compile(r"MySQL\s+[34]\.", re.I),
        "End-of-life MySQL version detected.",
        "Migrate to MySQL 8.x or a supported fork such as MariaDB.",
    ),
    (
        re.compile(r"Samba\s+[23]\.", re.I),
        "Older Samba version detected – potential SambaCry (CVE-2017-7494) risk.",
        "Upgrade Samba and apply CVE-2017-7494 patch immediately.",
    ),
    (
        re.compile(r"telnetd", re.I),
        "Telnet daemon detected – plaintext authentication in use.",
        "Disable telnetd and migrate all access to SSH.",
    ),
    (
        re.compile(r"wu-ftpd|wuftpd", re.I),
        "wu-ftpd detected – known vulnerable and end-of-life FTP server.",
        "Replace wu-ftpd with vsftpd or ProFTPD (latest version).",
    ),
]


# ── NSE script output patterns → Finding ──────────────────────────────────────
# Each entry: (script_name_pattern, output_pattern, type, description, severity, mitigation)
_NSE_RULES: List[tuple[re.Pattern, re.Pattern, str, str, str, str]] = [
    (
        re.compile(r"ftp-anon", re.I),
        re.compile(r"Anonymous FTP login allowed", re.I),
        "ANONYMOUS_ACCESS",
        "Anonymous FTP login is enabled – anyone can read/write without credentials.",
        "High",
        "Disable anonymous FTP in the server config (e.g. anonymous_enable=NO in vsftpd.conf).",
    ),
    (
        re.compile(r"ssl-cert", re.I),
        re.compile(r"Not valid after.*20(1[0-9]|2[0-3])", re.I),
        "SSL_ISSUE",
        "SSL/TLS certificate has expired.",
        "High",
        "Renew the certificate immediately and set up automatic renewal (e.g. Let's Encrypt + certbot).",
    ),
    (
        re.compile(r"ssl-enum-ciphers", re.I),
        re.compile(r"SSLv2|SSLv3|TLSv1\.0|TLSv1\.1", re.I),
        "SSL_ISSUE",
        "Deprecated SSL/TLS protocol version is still enabled.",
        "High",
        "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Only allow TLS 1.2 and TLS 1.3.",
    ),
    (
        re.compile(r"ssl-cert", re.I),
        re.compile(r"self.signed|unable to verify", re.I),
        "SSL_ISSUE",
        "Self-signed or unverifiable SSL certificate detected.",
        "Medium",
        "Replace the self-signed certificate with one issued by a trusted CA.",
    ),
    (
        re.compile(r"http-default-accounts", re.I),
        re.compile(r"Valid credentials|login successful", re.I),
        "DEFAULT_CREDENTIALS",
        "Service accepted default credentials – immediate account takeover risk.",
        "Critical",
        "Change all default credentials immediately. Enforce a strong password policy and enable MFA.",
    ),
    (
        re.compile(r"http-trace", re.I),
        re.compile(r"TRACE.*enabled|200 OK", re.I),
        "MISC",
        "HTTP TRACE method is enabled – can be used in cross-site tracing (XST) attacks.",
        "Medium",
        "Disable the TRACE method in the web server configuration.",
    ),
    (
        re.compile(r"http-put", re.I),
        re.compile(r"PUT.*allowed|201 Created", re.I),
        "MISC",
        "HTTP PUT method is enabled – attackers may be able to upload arbitrary files.",
        "High",
        "Disable the PUT method unless strictly required by the application.",
    ),
    (
        re.compile(r"http-git", re.I),
        re.compile(r"Git repository found|\.git", re.I),
        "MISC",
        "Exposed .git repository directory – source code and secrets may be leaked.",
        "Critical",
        "Block public access to the .git directory at the web server level.",
    ),
    (
        re.compile(r"http-shellshock", re.I),
        re.compile(r"VULNERABLE|shellshock", re.I),
        "MISC",
        "Shellshock (CVE-2014-6271) vulnerability detected in CGI scripts.",
        "Critical",
        "Update bash to a patched version and audit all CGI scripts.",
    ),
    (
        re.compile(r".*", re.I),               # catch-all for any script
        re.compile(r"VULNERABLE", re.I),
        "MISC",
        "NSE script reported a VULNERABLE state.",
        "High",
        "Review the full nmap output for this script and apply the recommended patch or mitigation.",
    ),
]


# ── Public API ─────────────────────────────────────────────────────────────────

def scan_ports(
    target: str,
    port_range: str = "1-1024",
    aggressive: bool = False,
) -> List[Finding]:
    """
    Run nmap against *target* and return a flat list of Findings.

    Parameters
    ----------
    target      : hostname, IP address, or full URL
    port_range  : nmap port spec  e.g. "1-1024", "80,443,8080", "1-65535"
    aggressive  : enables -A + vuln scripts (requires root/sudo on most systems)
    """
    host = _extract_host(target)
    nm   = nmap.PortScanner()
    args = _build_args(port_range, aggressive)

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

        if aggressive:
            findings.extend(_os_findings(scanned_host, info))

        for proto in info.all_protocols():
            for port, pdata in sorted(info[proto].items()):
                if pdata.get("state") != "open":
                    continue
                findings.extend(_analyse_port(scanned_host, proto, port, pdata))

    return findings


# ── Internal helpers ───────────────────────────────────────────────────────────

def _extract_host(target: str) -> str:
    if "://" in target:
        return urlparse(target).hostname or target
    return target


def _build_args(port_range: str, aggressive: bool) -> str:
    base = f"-p {port_range} -sV --open"
    if aggressive:
        scripts = (
            "vuln,ftp-anon,ssl-cert,ssl-enum-ciphers,"
            "http-default-accounts,http-trace,http-put,"
            "http-git,http-shellshock,http-headers"
        )
        return f"{base} -A --script={scripts}"
    return f"{base} -sC"


def _os_findings(host: str, info: Any) -> List[Finding]:
    findings = []
    osmatch = info.get("osmatch", [])
    if not osmatch:
        return findings
    best     = osmatch[0]
    os_name  = best.get("name", "Unknown")
    accuracy = best.get("accuracy", "?")
    findings.append(Finding(
        id="",
        type="OS_DETECTED",
        endpoint=host,
        description=(
            f"OS fingerprinted as '{os_name}' with {accuracy}% accuracy. "
            "Exposing OS information helps attackers target known vulnerabilities."
        ),
        severity="Info",
        mitigation=(
            "Harden TCP/IP stack settings to reduce fingerprinting accuracy. "
            "Ensure the OS and kernel are fully patched and up to date."
        ),
    ))
    return findings


def _analyse_port(
    host: str, proto: str, port: int, pdata: Dict[str, Any]
) -> List[Finding]:
    findings: List[Finding] = []

    service    = pdata.get("name", "")
    product    = pdata.get("product", "")
    version    = pdata.get("version", "")
    extrainfo  = pdata.get("extrainfo", "")
    scripts    = pdata.get("script", {})  # dict: script_name → output_str

    banner   = " ".join(filter(None, [product, version, extrainfo])).strip()
    endpoint = f"{host}:{port}/{proto}"

    severity, risk_note = _PORT_RISK.get(port, (_DEFAULT_PORT_SEVERITY, _DEFAULT_PORT_NOTE))

    # Build description
    parts = [f"Port {port}/{proto} is open."]
    if service: parts.append(f"Service: {service}.")
    if banner:  parts.append(f"Banner: {banner}.")
    parts.append(risk_note)

    findings.append(Finding(
        id="",
        type="OPEN_PORT",
        endpoint=endpoint,
        description=" ".join(parts),
        severity=severity,
        mitigation=(
            "Confirm this port is intentionally exposed. "
            "If unused, close it at the firewall or stop the service. "
            "Restrict access to trusted IP ranges where possible."
        ),
        raw_nmap_output=f"proto={proto} service={service} banner={banner}",
    ))

    # Check for outdated/weak service version
    if banner:
        findings.extend(_weak_service_findings(endpoint, banner))

    # Parse NSE script output
    for script_name, output in scripts.items():
        findings.extend(_nse_findings(endpoint, script_name, output))

    return findings


def _weak_service_findings(endpoint: str, banner: str) -> List[Finding]:
    findings = []
    for pattern, description, mitigation in _WEAK_SERVICE_PATTERNS:
        if pattern.search(banner):
            findings.append(Finding(
                id="",
                type="OUTDATED_SERVICE",
                endpoint=endpoint,
                description=f"{description} Detected banner: '{banner}'.",
                severity="High",
                mitigation=mitigation,
                raw_nmap_output=banner,
            ))
    return findings


def _nse_findings(endpoint: str, script_name: str, output: str) -> List[Finding]:
    findings = []
    for name_pat, out_pat, ftype, description, severity, mitigation in _NSE_RULES:
        if name_pat.search(script_name) and out_pat.search(output):
            findings.append(Finding(
                id="",
                type=ftype,
                endpoint=endpoint,
                description=f"[{script_name}] {description}",
                severity=severity,
                mitigation=mitigation,
                raw_nmap_output=output[:600],
            ))
            break  # one finding per script
    return findings


def _error_finding(host: str, msg: str) -> Finding:
    return Finding(
        id="",
        type="MISC",
        endpoint=host,
        description=f"Nmap scan failed: {msg}",
        severity="Info",
        mitigation=(
            "Ensure nmap is installed and accessible in PATH. "
            "OS detection and SYN scans require root/Administrator privileges."
        ),
    )