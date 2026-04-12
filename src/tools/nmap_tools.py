"""Network reconnaissance & port scanning via Nmap."""

from __future__ import annotations

import json
from typing import Any

import nmap
from langchain_core.tools import tool

from src.guardrails import validate_target
from src.logging import get_audit_logger


@tool
def nmap_scan(target: str, scan_type: str = "basic", ports: str | None = None) -> str:
    """Run an Nmap scan against a target host within the allowed subnet.

    Args:
        target: IP address or hostname to scan.
        scan_type: One of 'basic', 'service', 'vuln', 'stealth'.
        ports: Optional port range (e.g. '1-1000', '22,80,443').

    Returns:
        JSON string with scan results including open ports and services.
    """
    validate_target(target)
    audit = get_audit_logger()

    scanner = nmap.PortScanner()

    scan_args: dict[str, str] = {
        "basic": "-sT -T4",
        "service": "-sV -T4",
        "vuln": "-sV --script=vuln -T4",
        "stealth": "-sS -T2",
    }
    arguments = scan_args.get(scan_type, scan_args["basic"])
    if ports:
        arguments += f" -p {ports}"

    audit.record(
        "nmap_scan_start",
        tool="nmap",
        target=target,
        parameters={"scan_type": scan_type, "ports": ports, "arguments": arguments},
    )

    import time
    for attempt in range(1, 4):
        try:
            scanner.scan(hosts=target, arguments=arguments)
            break
        except nmap.PortScannerError as exc:
            if attempt == 3:
                error_msg = f"Nmap scan failed after 3 attempts: {exc}. Suggestion: Fall back to tcp_syn_scan, use -Pn, or try manual port enumeration."
                audit.record("nmap_scan_error", tool="nmap", target=target, result=error_msg)
                return json.dumps({"error": error_msg})
            time.sleep(2 ** attempt)

    results: dict[str, Any] = {}
    for host in scanner.all_hosts():
        host_data: dict[str, Any] = {
            "state": scanner[host].state(),
            "protocols": {},
        }
        for proto in scanner[host].all_protocols():
            ports_data = {}
            for port in sorted(scanner[host][proto]):
                port_info = scanner[host][proto][port]
                ports_data[port] = {
                    "state": port_info["state"],
                    "service": port_info.get("name", "unknown"),
                    "version": port_info.get("version", ""),
                    "product": port_info.get("product", ""),
                }
            host_data["protocols"][proto] = ports_data
        results[host] = host_data

    audit.record(
        "nmap_scan_complete",
        tool="nmap",
        target=target,
        result=f"Found {len(results)} host(s)",
    )

    return json.dumps(results, indent=2)


@tool
def nmap_os_detection(target: str) -> str:
    """Attempt OS detection on a target host.

    Args:
        target: IP address to fingerprint.

    Returns:
        JSON string with OS detection results.
    """
    validate_target(target)
    audit = get_audit_logger()

    scanner = nmap.PortScanner()
    audit.record("nmap_os_detect_start", tool="nmap", target=target)

    try:
        scanner.scan(hosts=target, arguments="-O -T4")
    except nmap.PortScannerError as exc:
        return json.dumps({"error": str(exc)})

    results = {}
    for host in scanner.all_hosts():
        os_matches = scanner[host].get("osmatch", [])
        results[host] = {
            "os_matches": [
                {"name": m["name"], "accuracy": m["accuracy"]}
                for m in os_matches[:5]
            ]
        }

    audit.record("nmap_os_detect_complete", tool="nmap", target=target)
    return json.dumps(results, indent=2)
