"""Low-level network tools using Scapy for packet crafting & analysis."""

from __future__ import annotations

import json

from langchain_core.tools import tool

from src.guardrails import validate_target
from src.logging import get_audit_logger


@tool
def ping_sweep(subnet: str) -> str:
    """Perform an ICMP ping sweep to discover live hosts on a subnet.

    Args:
        subnet: Target subnet in CIDR notation (e.g. '172.20.0.0/24').

    Returns:
        JSON list of responding hosts.
    """
    validate_target(subnet.split("/")[0])
    audit = get_audit_logger()
    audit.record("ping_sweep_start", tool="scapy", target=subnet)

    try:
        from scapy.all import IP, ICMP, sr, conf  # type: ignore[import-untyped]

        conf.verb = 0  # silence scapy output
        ans, _ = sr(IP(dst=subnet) / ICMP(), timeout=3, retry=1)

        live_hosts = sorted({rcv.src for _, rcv in ans})
        audit.record(
            "ping_sweep_complete",
            tool="scapy",
            target=subnet,
            result=f"Found {len(live_hosts)} live host(s)",
        )
        return json.dumps({"live_hosts": live_hosts, "count": len(live_hosts)}, indent=2)
    except Exception as exc:
        audit.record("ping_sweep_error", tool="scapy", target=subnet, result=str(exc))
        return json.dumps({"error": str(exc)})


@tool
def tcp_syn_scan(target: str, ports: str = "1-1024") -> str:
    """Perform a TCP SYN (half-open) scan using Scapy.

    Args:
        target: Target IP address.
        ports: Port range to scan (e.g. '1-1024' or '22,80,443').

    Returns:
        JSON with open ports discovered.
    """
    validate_target(target)
    audit = get_audit_logger()
    audit.record("syn_scan_start", tool="scapy", target=target, parameters={"ports": ports})

    try:
        from scapy.all import IP, TCP, sr, conf  # type: ignore[import-untyped]

        conf.verb = 0

        # Parse port range
        if "-" in ports:
            start, end = ports.split("-")
            port_list = list(range(int(start), int(end) + 1))
        else:
            port_list = [int(p.strip()) for p in ports.split(",")]

        ans, _ = sr(IP(dst=target) / TCP(dport=port_list, flags="S"), timeout=5)

        open_ports = []
        for _, rcv in ans:
            if rcv.haslayer(TCP) and rcv[TCP].flags == 0x12:  # SYN-ACK
                open_ports.append(rcv[TCP].sport)

        audit.record(
            "syn_scan_complete",
            tool="scapy",
            target=target,
            result=f"Found {len(open_ports)} open port(s)",
        )
        return json.dumps({"target": target, "open_ports": sorted(open_ports)}, indent=2)
    except Exception as exc:
        audit.record("syn_scan_error", tool="scapy", target=target, result=str(exc))
        return json.dumps({"error": str(exc)})


@tool
def banner_grab(target: str, port: int) -> str:
    """Grab the service banner from a specific TCP port.

    Args:
        target: Target IP address.
        port: Port number to connect to.

    Returns:
        JSON with the banner text received.
    """
    validate_target(target)
    audit = get_audit_logger()
    audit.record("banner_grab_start", tool="network", target=target, parameters={"port": port})

    import socket

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        sock.send(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="replace")
        sock.close()

        audit.record("banner_grab_complete", tool="network", target=target, result=banner[:200])
        return json.dumps({"target": target, "port": port, "banner": banner}, indent=2)
    except Exception as exc:
        audit.record("banner_grab_error", tool="network", target=target, result=str(exc))
        return json.dumps({"error": str(exc)})
