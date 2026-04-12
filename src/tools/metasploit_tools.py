"""Metasploit Framework integration via RPC."""

from __future__ import annotations

import json
from typing import Any

from langchain_core.tools import tool

from src.guardrails import validate_target
from src.logging import get_audit_logger


def _get_msf_client() -> Any:
    """Lazy-connect to the Metasploit RPC daemon with retries."""
    from pymetasploit3.msfrpc import MsfRpcClient
    import time

    from src.config import get_settings

    cfg = get_settings().metasploit
    last_err = None
    for attempt in range(1, 4):
        try:
            return MsfRpcClient(cfg.password, server=cfg.host, port=cfg.port, username=cfg.user, ssl=False)
        except Exception as exc:
            last_err = exc
            time.sleep(2 ** attempt)
    raise ConnectionError(f"Failed to connect to MSF RPC after 3 attempts: {last_err}")


@tool
def msf_search_exploits(query: str) -> str:
    """Search the Metasploit module database for exploits matching a query.

    Args:
        query: Search term (e.g. 'apache struts', 'ms17-010', 'tomcat').

    Returns:
        JSON list of matching modules with name, rank, and description.
    """
    audit = get_audit_logger()
    audit.record("msf_search_start", tool="metasploit", parameters={"query": query})

    try:
        client = _get_msf_client()
        modules = client.modules.search(query)
    except Exception as exc:
        error_msg = f"Metasploit RPC unavailable or search failed: {exc}. Suggestion: Fall back to nmap scripting engine (NSE) or manual enumeration."
        audit.record("msf_search_error", tool="metasploit", result=error_msg)
        return json.dumps({"error": error_msg})

    results = [
        {
            "fullname": m["fullname"],
            "type": m["type"],
            "rank": m.get("rank", "unknown"),
            "name": m["name"],
        }
        for m in modules[:20]  # cap at 20 results
    ]

    audit.record(
        "msf_search_complete",
        tool="metasploit",
        result=f"Found {len(results)} module(s) for '{query}'",
    )
    return json.dumps(results, indent=2)


@tool
def msf_run_exploit(
    module_name: str,
    target_host: str,
    target_port: int,
    payload: str = "generic/shell_reverse_tcp",
    options: dict[str, str] | None = None,
) -> str:
    """Execute a Metasploit exploit module against a target.

    ⚠️ REQUIRES HUMAN APPROVAL — this is a destructive action.

    Args:
        module_name: Full module path (e.g. 'exploit/multi/http/tomcat_mgr_upload').
        target_host: Target IP address (must be in allowed subnet).
        target_port: Target port number.
        payload: Metasploit payload to use.
        options: Additional module options as key-value pairs.

    Returns:
        JSON with exploit execution results including session info if successful.
    """
    validate_target(target_host)
    audit = get_audit_logger()

    params = {
        "module": module_name,
        "target": target_host,
        "port": target_port,
        "payload": payload,
        "options": options or {},
    }
    audit.record(
        "msf_exploit_start",
        tool="metasploit",
        target=target_host,
        parameters=params,
        risk_level="critical",
    )

    try:
        client = _get_msf_client()
        exploit = client.modules.use("exploit", module_name)

        exploit["RHOSTS"] = target_host
        exploit["RPORT"] = target_port

        if options:
            for k, v in options.items():
                exploit[k] = v

        payload_mod = client.modules.use("payload", payload)
        result = exploit.execute(payload=payload_mod)

        # Check for new sessions
        sessions = client.sessions.list
        active = {
            sid: {
                "type": info["type"],
                "target_host": info["target_host"],
                "via_exploit": info["via_exploit"],
            }
            for sid, info in sessions.items()
        }

        output = {
            "job_id": result.get("job_id"),
            "uuid": result.get("uuid"),
            "active_sessions": active,
            "status": "exploit_launched",
        }

        audit.record(
            "msf_exploit_complete",
            tool="metasploit",
            target=target_host,
            result=json.dumps(output),
            risk_level="critical",
        )
        return json.dumps(output, indent=2)

    except Exception as exc:
        error_msg = f"Exploit failed or MSF unreachable: {exc}. Suggestion: Check Metasploit connectivity or use an alternative manual exploitation method."
        audit.record(
            "msf_exploit_error",
            tool="metasploit",
            target=target_host,
            result=error_msg,
            risk_level="critical",
        )
        return json.dumps({"error": error_msg})


@tool
def msf_list_sessions() -> str:
    """List all active Metasploit sessions.

    Returns:
        JSON with active session details.
    """
    audit = get_audit_logger()
    audit.record("msf_list_sessions", tool="metasploit")

    client = _get_msf_client()
    sessions = client.sessions.list

    return json.dumps(
        {
            sid: {
                "type": info["type"],
                "target_host": info["target_host"],
                "via_exploit": info["via_exploit"],
                "info": info.get("info", ""),
            }
            for sid, info in sessions.items()
        },
        indent=2,
    )
