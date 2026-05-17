"""Agent state definition for the Autonomous AI Red Teaming Agent.

This TypedDict defines the shared state passed between all nodes in the LangGraph.
Includes strategic planning fields for dynamic, phase-aware decision-making,
error tracking for self-correction, and kill-switch support.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import asdict, dataclass, field
from typing import Annotated, Any, Literal, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages

# ── Kill-chain phases (ordered) ──────────────────────────────────────────────
PHASES = [
    "reconnaissance",
    "scanning",
    "exploitation",
    "post_exploitation",
    "reporting",
]

# Extended phases include triage & remediation between post-exploit and final report
EXTENDED_PHASES = [
    "reconnaissance",
    "scanning",
    "exploitation",
    "post_exploitation",
    "triage",
    "remediation",
    "reporting",
]

SeverityLevel = Literal["critical", "high", "medium", "low", "info"]


@dataclass
class Finding:
    """Represents a discovered security finding."""

    target: str
    vulnerability: str
    severity: str  # critical, high, medium, low, info
    port: int | None = None
    service: str | None = None
    evidence: str = ""
    remediation: str = ""
    cve: str | None = None
    exploited: bool = False
    confidence: float = 0.0  # 0.0–1.0 — how certain the agent is
    risk_level: str = "low"  # tool-reported risk level
    recommended_next_phase: str = ""  # suggested next phase from the tool

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to a dictionary for state storage."""
        return asdict(self)


@dataclass
class StrategyEntry:
    """Records a strategic decision made by the planner."""

    phase: str
    decision: str
    reasoning: str
    timestamp: str = ""
    risk_score_at_time: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DiscoveredTarget:
    """A target discovered during reconnaissance."""

    ip: str
    hostname: str = ""
    open_ports: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    os_guess: str = ""
    priority: str = "medium"  # high, medium, low — attack priority

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ErrorRecord:
    """Records a tool or phase failure for self-correction tracking."""

    phase: str
    tool_name: str
    error_message: str
    timestamp: str = ""
    retry_count: int = 0
    recovered: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AgentState(TypedDict):
    """State schema for the red teaming agent graph.

    All nodes read from and write to this state.
    """

    # ── Core LangGraph field ─────────────────────────────────────────────
    messages: Annotated[list[BaseMessage], add_messages]

    # ── Phase management ─────────────────────────────────────────────────
    current_phase: str
    # Valid: "reconnaissance", "scanning", "exploitation",
    #        "post_exploitation", "triage", "remediation", "reporting"

    # ── Findings & intelligence ──────────────────────────────────────────
    findings: list[dict[str, Any]]
    # List of Finding objects (as dicts)

    discovered_targets: list[dict[str, Any]]
    # List of DiscoveredTarget objects (as dicts) — built during recon

    # ── Step tracking ────────────────────────────────────────────────────
    step_count: int
    max_steps: int

    # ── Risk & scoring ───────────────────────────────────────────────────
    risk_score: float
    # 0–100, dynamically computed. Drives escalation decisions.

    # ── Active exploit sessions ──────────────────────────────────────────
    active_sessions: dict[str, Any]
    # Keyed by session ID → {target, exploit_module, shell_type, ...}

    sessions: list[dict[str, Any]]
    # Legacy: flat list of Metasploit sessions for backward compatibility

    # ── Strategic planning ───────────────────────────────────────────────
    strategy_history: list[dict[str, Any]]
    # List of StrategyEntry dicts — full audit of planner decisions

    plan: str
    # Current high-level attack plan text

    # ── Safety & scope ───────────────────────────────────────────────────
    approved_actions: list[str]
    allowed_subnet: str
    targets: list[str]  # user-supplied target IPs / subnets

    # ── Human-in-the-loop ────────────────────────────────────────────────
    human_feedback: str

    # ── Engagement controls ──────────────────────────────────────────────
    aggression_level: str
    # "low" = recon/scan only, "medium" = exploit with caution, "high" = full auto
    stealth_mode: bool
    # True = prefer SYN scans, slower timing, avoid noisy tools

    # ── Error tracking & self-correction (production-grade) ──────────────
    error_log: list[dict[str, Any]]
    # List of ErrorRecord dicts — every tool/phase failure

    phase_failures: dict[str, int]
    # Phase name → number of failures in that phase

    consecutive_failures: int
    # Running count of back-to-back failures (reset on success)

    total_errors: int
    # Lifetime error count for the engagement

    kill_switch_triggered: bool
    # True if risk_score > threshold or too many failures → halt

    kill_switch_reason: str
    # Human-readable reason the kill switch was flipped

    # ── Critic / self-awareness ──────────────────────────────────────────
    critic_feedback: list[dict[str, Any]]
    # List of critic observations: {issue, suggestion, timestamp}

    last_successful_phase: str
    # Tracks the most recent phase that completed without errors


# Maximum consecutive failures before the critic forces a phase skip
MAX_CONSECUTIVE_FAILURES = 3

# Risk score threshold that triggers the automatic kill switch
KILL_SWITCH_RISK_THRESHOLD = 80

# Maximum total errors before forced shutdown
KILL_SWITCH_ERROR_THRESHOLD = 10


def initial_state(
    targets: list[str] | None = None,
    max_steps: int = 50,
    allowed_subnet: str = "172.28.0.0/16",
    aggression_level: str = "medium",
    stealth_mode: bool = False,
) -> AgentState:
    """Initialize a fresh agent state with all required fields."""
    # Pre-populate discovered_targets with user targets so the planner doesn't get stuck if ping sweep fails
    initial_discovered = []
    if targets:
        for t in targets:
            initial_discovered.append({
                "ip": t,
                "hostname": "",
                "open_ports": [],
                "services": [],
                "os_guess": "",
                "priority": "medium",
            })

    return {
        "messages": [],
        "current_phase": "reconnaissance",
        "findings": [],
        "discovered_targets": initial_discovered,
        "step_count": 0,
        "max_steps": max_steps,
        "risk_score": 0.0,
        "active_sessions": {},
        "sessions": [],
        "strategy_history": [],
        "plan": "",
        "approved_actions": [],
        "allowed_subnet": allowed_subnet,
        "targets": targets or [],
        "human_feedback": "",
        "aggression_level": aggression_level,
        "stealth_mode": stealth_mode,
        # Error tracking
        "error_log": [],
        "phase_failures": {},
        "consecutive_failures": 0,
        "total_errors": 0,
        "kill_switch_triggered": False,
        "kill_switch_reason": "",
        # Critic / self-awareness
        "critic_feedback": [],
        "last_successful_phase": "",
    }


# ── Scoring utilities ────────────────────────────────────────────────────────

SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 25.0,
    "high": 15.0,
    "medium": 8.0,
    "low": 3.0,
    "info": 1.0,
}


def calculate_risk_score(findings: list[dict[str, Any]]) -> float:
    """Compute an overall risk score (0–100) from the current findings.

    Uses a weighted-sum approach capped at 100.
    """
    if not findings:
        return 0.0
    total = sum(
        SEVERITY_WEIGHTS.get(f.get("severity", "info"), 1.0)
        for f in findings
    )
    return min(total, 100.0)


def calculate_engagement_success(state: AgentState) -> dict[str, Any]:
    """Compute a multi-dimensional success score for the engagement.

    Returns a dict with individual metrics and an overall percentage.
    """
    findings = state.get("findings", [])
    targets = state.get("targets", [])
    discovered = state.get("discovered_targets", [])
    sessions = state.get("active_sessions", {})
    strategy = state.get("strategy_history", [])

    # 1. Discovery rate — how many targets were actually found
    discovery_rate = (len(discovered) / max(len(targets), 1)) * 100.0

    # 2. Finding density — weighted findings per target
    finding_score = min(calculate_risk_score(findings), 100.0)

    # 3. Exploitation success — fraction of discovered targets with sessions
    exploited_ips = {s.get("target") for s in sessions.values()} if sessions else set()
    discovered_ips = {d.get("ip") for d in discovered} if discovered else set()
    exploitation_rate = (
        (len(exploited_ips & discovered_ips) / max(len(discovered_ips), 1)) * 100.0
    )

    # 4. Phase completion — how far through the kill-chain
    phase = state.get("current_phase", "reconnaissance")
    phase_idx = (
        EXTENDED_PHASES.index(phase)
        if phase in EXTENDED_PHASES
        else 0
    )
    phase_completion = ((phase_idx + 1) / len(EXTENDED_PHASES)) * 100.0

    # 5. Strategic depth — number of planner decisions
    strategic_depth = min(len(strategy) * 10, 100.0)

    # Weighted overall
    overall = (
        discovery_rate * 0.15
        + finding_score * 0.30
        + exploitation_rate * 0.25
        + phase_completion * 0.20
        + strategic_depth * 0.10
    )

    return {
        "discovery_rate": round(discovery_rate, 1),
        "finding_score": round(finding_score, 1),
        "exploitation_rate": round(exploitation_rate, 1),
        "phase_completion": round(phase_completion, 1),
        "strategic_depth": round(strategic_depth, 1),
        "overall": round(min(overall, 100.0), 1),
    }
