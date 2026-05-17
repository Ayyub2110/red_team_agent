import json
from typing import Annotated
from langchain_core.tools import tool
from langgraph.prebuilt import InjectedState
from langgraph.types import Command

@tool
def record_finding(
    target: str,
    vulnerability: str,
    severity: str,
    state: Annotated[dict, InjectedState],
    port: int = 0,
    service: str = "",
    evidence: str = "",
    remediation: str = ""
) -> Command:
    """Record a verified vulnerability finding to the agent's memory.
    
    You MUST call this tool whenever you discover an open port, service, or vulnerability
    so that the strategic planner knows you found something.
    
    Args:
        target: IP address or hostname.
        vulnerability: Description of the finding or vulnerability.
        severity: 'critical', 'high', 'medium', 'low', or 'info'.
        state: Injected state (do not pass this argument).
        port: Port number if applicable (default 0).
        service: Service name (e.g. 'http', 'ssh').
        evidence: Proof of the finding.
        remediation: Suggested fix.
    """
    current_findings = list(state.get("findings", []))
    finding = {
        "target": target,
        "vulnerability": vulnerability,
        "severity": severity,
        "port": port,
        "service": service,
        "evidence": evidence,
        "remediation": remediation,
    }
    current_findings.append(finding)
    
    # Return a Command to update the findings in the state
    return Command(
        update={"findings": current_findings}
    )
