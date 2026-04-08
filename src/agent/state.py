"""Agent state definition for the Autonomous AI Red Teaming Agent.

This TypedDict defines the shared state passed between all nodes in the LangGraph.
"""

from typing import TypedDict, Annotated, List, Dict, Any
from langgraph.graph.message import add_messages
from langchain_core.messages import BaseMessage


class AgentState(TypedDict):
    """State schema for the red teaming agent graph.

    All nodes read from and write to this state.
    """

    # Core LangGraph field - conversation history (messages are appended automatically)
    messages: Annotated[list[BaseMessage], add_messages]

    # Red teaming workflow fields
    current_phase: str
    # Valid values: "recon", "scanning", "exploitation", "post_exploitation", "triage", "remediation"

    findings: List[Dict[str, Any]]
    # Example finding: {
    #   "target": "172.28.0.10",
    #   "vuln_type": "SQL Injection",
    #   "evidence": "Error-based SQLi detected...",
    #   "severity": "High",
    #   "remediation": "Use parameterized queries..."
    # }

    step_count: int

    max_steps: int = 15

    approved_actions: List[str]
    # Track tool calls that required explicit human approval

    allowed_subnet: str = "172.28.0.0/16"
    # Safety guardrail: agent can only target IPs in this subnet

    targets: List[str]
    # List of discovered or provided target IPs/hostnames
