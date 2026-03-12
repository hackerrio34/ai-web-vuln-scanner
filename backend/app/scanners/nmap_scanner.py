from typing import List, Dict, Any
import nmap  # python-nmap library

from app.schemas.scan import Finding


def scan_ports(target_host: str, ports: str = "1-1024") -> List[Finding]:
    """
    Run a basic Nmap scan against the target host and return Findings
    for open ports.

    :param target_host: hostname or IP (e.g. "example.com" or "192.168.1.10")
    :param ports: port range string in Nmap format, e.g. "1-1024" or "80,443,8080"
    """
    nm = nmap.PortScanner()
    findings: List[Finding] = []

    try:
        nm.scan(hosts=target_host, ports=ports)
    except Exception:
        # If Nmap fails (not installed / no permission),
        # just return no findings for now.
        return findings

    for host in nm.all_hosts():
        if nm[host].state() != "up":
            continue

        for proto in nm[host].all_protocols():
            ports_dict: Dict[int, Dict[str, Any]] = nm[host][proto]
            for port, port_data in ports_dict.items():
                state = port_data.get("state", "unknown")
                if state != "open":
                    continue

                service_name = port_data.get("name", "")
                product = port_data.get("product", "")
                version = port_data.get("version", "")

                description_parts = [f"Port {port}/{proto} is open."]
                if service_name:
                    description_parts.append(f"Service: {service_name}")
                if product or version:
                    description_parts.append(
                        f"Product: {product} {version}".strip()
                    )

                description = " ".join(description_parts)

                mitigation = (
                    "Verify that this port and service are required. If not, "
                    "close the port at the firewall or stop the service. "
                    "Ensure the service is patched and restricted to trusted "
                    "networks only."
                )

                findings.append(
                    Finding(
                        id="",  # will be set in service layer
                        type="OPEN_PORT",
                        endpoint=f"{host}:{port}",
                        description=description,
                        severity=_severity_for_port(port),
                        mitigation=mitigation,
                    )
                )

    return findings


def _severity_for_port(port: int) -> str:
    """
    Very simple severity logic based on common service ports.
    """
    high_risk_ports = {22, 23, 80, 443, 3306, 3389, 5432}
    medium_risk_ports = {21, 25, 110, 143, 8080}

    if port in high_risk_ports:
        return "High"
    if port in medium_risk_ports:
        return "Medium"
    if 1 <= port <= 1024:
        return "Medium"
    return "Low"
