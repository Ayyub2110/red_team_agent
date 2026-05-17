"""Adaptive Strategy Engine for the Autonomous AI Red Team Agent.

Provides context-aware tool selection and attack approach planning based on:
- Target classification (web, SSH, Windows, network device, etc.)
- Previous findings and their severity
- Current risk score and engagement progression
- Stealth requirements and aggression level
- Specialist routing (web exploitation vs network pivoting)

All functions are deterministic — no LLM calls. This engine runs before
each phase node to tailor the ReAct agent's available tools and directive.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# ── Target type classification ───────────────────────────────────────────────

TARGET_TYPE_WEB = "web"
TARGET_TYPE_SSH = "ssh"
TARGET_TYPE_WINDOWS = "windows"
TARGET_TYPE_DATABASE = "database"
TARGET_TYPE_NETWORK = "network_device"
TARGET_TYPE_UNKNOWN = "unknown"

# Port → service type mapping for automatic classification
PORT_TO_SERVICE_TYPE: dict[int, str] = {
    22: TARGET_TYPE_SSH,
    80: TARGET_TYPE_WEB,
    443: TARGET_TYPE_WEB,
    3000: TARGET_TYPE_WEB,  # Node.js apps (e.g., Juice Shop)
    3306: TARGET_TYPE_DATABASE,
    5432: TARGET_TYPE_DATABASE,
    8080: TARGET_TYPE_WEB,
    8443: TARGET_TYPE_WEB,
    445: TARGET_TYPE_WINDOWS,
    135: TARGET_TYPE_WINDOWS,
    139: TARGET_TYPE_WINDOWS,
    3389: TARGET_TYPE_WINDOWS,  # RDP
    23: TARGET_TYPE_NETWORK,   # Telnet
    161: TARGET_TYPE_NETWORK,   # SNMP
}

# Phase → tool selection matrix per target type
# Keys: (phase, target_type) → recommended tool names
TOOL_SELECTION_MATRIX: dict[tuple[str, str], list[str]] = {
    # ── Reconnaissance ───────────────────────────────────────────────────
    ("reconnaissance", TARGET_TYPE_WEB): [
        "ping_sweep", "banner_grab", "http_get",
    ],
    ("reconnaissance", TARGET_TYPE_SSH): [
        "ping_sweep", "banner_grab",
    ],
    ("reconnaissance", TARGET_TYPE_WINDOWS): [
        "ping_sweep", "nmap_os_detection", "banner_grab",
    ],
    ("reconnaissance", TARGET_TYPE_UNKNOWN): [
        "ping_sweep", "banner_grab", "nmap_os_detection",
    ],
    # ── Scanning ─────────────────────────────────────────────────────────
    ("scanning", TARGET_TYPE_WEB): [
        "nmap_scan", "http_get", "http_post", "directory_bruteforce",
    ],
    ("scanning", TARGET_TYPE_SSH): [
        "nmap_scan", "banner_grab", "tcp_syn_scan",
    ],
    ("scanning", TARGET_TYPE_WINDOWS): [
        "nmap_scan", "nmap_os_detection", "tcp_syn_scan",
    ],
    ("scanning", TARGET_TYPE_DATABASE): [
        "nmap_scan", "banner_grab",
    ],
    ("scanning", TARGET_TYPE_UNKNOWN): [
        "nmap_scan", "tcp_syn_scan", "http_get", "banner_grab",
    ],
    # ── Exploitation ─────────────────────────────────────────────────────
    ("exploitation", TARGET_TYPE_WEB): [
        "msf_search_exploits", "msf_run_exploit", "msf_list_sessions",
        "http_get", "http_post",
    ],
    ("exploitation", TARGET_TYPE_SSH): [
        "msf_search_exploits", "msf_run_exploit", "msf_list_sessions",
    ],
    ("exploitation", TARGET_TYPE_WINDOWS): [
        "msf_search_exploits", "msf_run_exploit", "msf_list_sessions",
    ],
    ("exploitation", TARGET_TYPE_UNKNOWN): [
        "msf_search_exploits", "msf_run_exploit", "msf_list_sessions",
        "http_get",
    ],
    # ── Post-exploitation ────────────────────────────────────────────────
    ("post_exploitation", TARGET_TYPE_WEB): [
        "http_get", "http_post", "directory_bruteforce", "msf_list_sessions",
    ],
    ("post_exploitation", TARGET_TYPE_SSH): [
        "banner_grab", "msf_list_sessions",
    ],
    ("post_exploitation", TARGET_TYPE_UNKNOWN): [
        "http_get", "banner_grab", "msf_list_sessions",
    ],
}


# ── Data structures ──────────────────────────────────────────────────────────

@dataclass
class TargetProfile:
    """Intelligence profile for a discovered target."""

    ip: str
    target_type: str = TARGET_TYPE_UNKNOWN
    open_ports: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    os_guess: str = ""
    priority: str = "medium"
    finding_count: int = 0
    critical_findings: int = 0
    has_session: bool = False
    specialist: str = ""  # "web" or "network" or ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StrategyRecommendation:
    """Output of the adaptive strategy engine for a given phase/state."""

    phase: str
    recommended_tools: list[str]
    approach: str  # "aggressive_scan", "stealth_scan", "targeted_exploit", etc.
    primary_targets: list[str]  # IPs to focus on
    specialist: str  # "web_specialist" | "network_specialist" | "general"
    risk_assessment: str  # brief text
    tool_rationale: str  # why these tools were chosen

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ══════════════════════════════════════════════════════════════════════════════
# CLASSIFICATION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def classify_target(target: dict[str, Any]) -> str:
    """Determine the target type based on discovered ports and services.

    Uses a voting system: each open port casts a vote for its service type.
    The type with the most votes wins.
    """
    ports = target.get("open_ports", [])
    services = target.get("services", [])

    if not ports and not services:
        return TARGET_TYPE_UNKNOWN

    votes: dict[str, int] = {}

    # Vote based on ports
    for port in ports:
        stype = PORT_TO_SERVICE_TYPE.get(port, TARGET_TYPE_UNKNOWN)
        votes[stype] = votes.get(stype, 0) + 1

    # Vote based on service strings
    service_keywords: dict[str, str] = {
        "http": TARGET_TYPE_WEB,
        "https": TARGET_TYPE_WEB,
        "apache": TARGET_TYPE_WEB,
        "nginx": TARGET_TYPE_WEB,
        "iis": TARGET_TYPE_WINDOWS,
        "ssh": TARGET_TYPE_SSH,
        "openssh": TARGET_TYPE_SSH,
        "mysql": TARGET_TYPE_DATABASE,
        "postgres": TARGET_TYPE_DATABASE,
        "microsoft": TARGET_TYPE_WINDOWS,
        "smb": TARGET_TYPE_WINDOWS,
        "telnet": TARGET_TYPE_NETWORK,
        "snmp": TARGET_TYPE_NETWORK,
    }
    for svc in services:
        svc_lower = svc.lower()
        for keyword, stype in service_keywords.items():
            if keyword in svc_lower:
                votes[stype] = votes.get(stype, 0) + 2  # Service names are stronger signals

    if not votes:
        return TARGET_TYPE_UNKNOWN

    # Return the type with the highest vote count
    return max(votes, key=votes.get)  # type: ignore[arg-type]


def classify_all_targets(
    discovered_targets: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    sessions: dict[str, Any],
) -> list[TargetProfile]:
    """Build enriched profiles for all discovered targets."""
    profiles: list[TargetProfile] = []

    for target in discovered_targets:
        ip = target.get("ip", "")
        target_type = classify_target(target)

        # Count findings for this target
        target_findings = [f for f in findings if f.get("target") == ip]
        critical = sum(1 for f in target_findings if f.get("severity") == "critical")

        # Check for active sessions
        has_session = any(s.get("target") == ip for s in sessions.values()) if sessions else False

        # Determine specialist
        specialist = ""
        if target_type == TARGET_TYPE_WEB:
            specialist = "web_specialist"
        elif target_type in (TARGET_TYPE_SSH, TARGET_TYPE_WINDOWS, TARGET_TYPE_NETWORK):
            specialist = "network_specialist"

        # Priority calculation
        priority = "low"
        if critical > 0 or has_session:
            priority = "high"
        elif len(target_findings) > 0:
            priority = "medium"

        profiles.append(TargetProfile(
            ip=ip,
            target_type=target_type,
            open_ports=target.get("open_ports", []),
            services=target.get("services", []),
            os_guess=target.get("os_guess", ""),
            priority=priority,
            finding_count=len(target_findings),
            critical_findings=critical,
            has_session=has_session,
            specialist=specialist,
        ))

    return profiles


# ══════════════════════════════════════════════════════════════════════════════
# SPECIALIST ROUTING
# ══════════════════════════════════════════════════════════════════════════════

SPECIALIST_WEB_TOOLS = [
    "http_get",
    "http_post",
    "directory_bruteforce",
    "nmap_scan",
    "msf_search_exploits",
    "msf_run_exploit",
    "msf_list_sessions",
    "record_finding",
]

SPECIALIST_NETWORK_TOOLS = [
    "nmap_scan",
    "tcp_syn_scan",
    "nmap_os_detection",
    "banner_grab",
    "msf_search_exploits",
    "msf_run_exploit",
    "msf_list_sessions",
    "record_finding",
]


def determine_specialist(profiles: list[TargetProfile]) -> str:
    """Decide which specialist sub-agent should handle the current targets.

    Returns "web_specialist", "network_specialist", or "general".
    """
    if not profiles:
        return "general"

    # Count by specialist type, weighted by priority
    web_score = 0
    network_score = 0

    priority_weights = {"high": 3, "medium": 2, "low": 1}

    for p in profiles:
        weight = priority_weights.get(p.priority, 1)
        if p.specialist == "web_specialist":
            web_score += weight
        elif p.specialist == "network_specialist":
            network_score += weight

    if web_score > network_score and web_score > 0:
        return "web_specialist"
    elif network_score > web_score and network_score > 0:
        return "network_specialist"
    return "general"


def get_specialist_tools(specialist: str) -> list[str]:
    """Return the tool list for a given specialist."""
    if specialist == "web_specialist":
        return SPECIALIST_WEB_TOOLS
    elif specialist == "network_specialist":
        return SPECIALIST_NETWORK_TOOLS
    return []  # General = use phase default tools


# ══════════════════════════════════════════════════════════════════════════════
# ADAPTIVE STRATEGY ENGINE — MAIN FUNCTION
# ══════════════════════════════════════════════════════════════════════════════

def compute_strategy(state: dict[str, Any]) -> StrategyRecommendation:
    """Compute the optimal strategy for the current engagement state.

    This is the main entry point called by the graph before each phase.
    It analyses the full state and returns a StrategyRecommendation with:
    - Which tools to prioritise
    - What approach to take (aggressive, stealth, targeted)
    - Which targets to focus on
    - Which specialist should handle this phase
    """
    phase = state.get("current_phase", "reconnaissance")
    findings = state.get("findings", [])
    discovered = state.get("discovered_targets", [])
    sessions = state.get("active_sessions", {})
    risk = state.get("risk_score", 0.0)
    aggression = state.get("aggression_level", "medium")
    stealth = state.get("stealth_mode", False)
    consec_fail = state.get("consecutive_failures", 0)
    error_log = state.get("error_log", [])

    # ── Classify targets ─────────────────────────────────────────────────
    profiles = classify_all_targets(discovered, findings, sessions)

    # ── Determine specialist ─────────────────────────────────────────────
    specialist = determine_specialist(profiles)

    # ── Determine approach ───────────────────────────────────────────────
    approach = _determine_approach(phase, risk, aggression, stealth, consec_fail)

    # ── Select tools ─────────────────────────────────────────────────────
    recommended_tools = _select_tools(
        phase, profiles, specialist, stealth, error_log,
    )

    # ── Prioritise targets ───────────────────────────────────────────────
    primary_targets = _prioritise_targets(profiles, phase)

    # ── Risk assessment ──────────────────────────────────────────────────
    risk_text = _build_risk_assessment(risk, phase, len(findings), consec_fail)

    # ── Tool rationale ───────────────────────────────────────────────────
    tool_rationale = _build_tool_rationale(profiles, specialist, approach, stealth)

    return StrategyRecommendation(
        phase=phase,
        recommended_tools=recommended_tools,
        approach=approach,
        primary_targets=primary_targets,
        specialist=specialist,
        risk_assessment=risk_text,
        tool_rationale=tool_rationale,
    )


# ── Internal helpers ─────────────────────────────────────────────────────────

def _determine_approach(
    phase: str,
    risk: float,
    aggression: str,
    stealth: bool,
    consec_fail: int,
) -> str:
    """Choose the tactical approach for the current situation."""
    if consec_fail >= 3:
        return "fallback_conservative"

    if stealth and phase in ("reconnaissance", "scanning"):
        return "stealth_scan"

    if phase == "exploitation":
        if aggression == "high":
            return "aggressive_exploit"
        elif risk >= 60:
            return "targeted_exploit"
        return "cautious_exploit"

    if phase == "post_exploitation":
        return "careful_enumeration"

    if aggression == "high" and phase == "scanning":
        return "aggressive_scan"

    return "standard"


def _select_tools(
    phase: str,
    profiles: list[TargetProfile],
    specialist: str,
    stealth: bool,
    error_log: list[dict[str, Any]],
) -> list[str]:
    """Select tools based on target profiles, specialist routing, and errors."""
    tools: set[str] = set()

    # 1. Specialist tools take precedence
    specialist_tools = get_specialist_tools(specialist)
    if specialist_tools:
        tools.update(specialist_tools)

    # 2. Add target-type specific tools from the matrix
    for profile in profiles:
        key = (phase, profile.target_type)
        matrix_tools = TOOL_SELECTION_MATRIX.get(key, [])
        tools.update(matrix_tools)

    # 3. Fallback: if no specific tools, add phase defaults
    if not tools:
        key_default = (phase, TARGET_TYPE_UNKNOWN)
        tools.update(TOOL_SELECTION_MATRIX.get(key_default, []))

    # 4. Stealth adjustments: prefer SYN scan over connect scan
    if stealth:
        if "nmap_scan" in tools:
            tools.add("tcp_syn_scan")  # Ensure stealth option available

    # 5. Error-driven fallback: if MSF tools keep failing, remove them
    msf_errors = sum(1 for e in error_log if e.get("tool_name", "").startswith("msf_"))
    if msf_errors >= 2:
        tools -= {"msf_run_exploit", "msf_search_exploits", "msf_list_sessions"}
        # Add manual alternatives
        tools.update({"nmap_scan", "http_get", "banner_grab"})

    return sorted(tools)


def _prioritise_targets(profiles: list[TargetProfile], phase: str) -> list[str]:
    """Return target IPs ordered by priority for the current phase."""
    if not profiles:
        return []

    # Sort: high priority first, then by finding_count (descending)
    priority_order = {"high": 0, "medium": 1, "low": 2}
    sorted_profiles = sorted(
        profiles,
        key=lambda p: (priority_order.get(p.priority, 3), -p.finding_count),
    )

    # In exploitation, only targets with findings are interesting
    if phase == "exploitation":
        sorted_profiles = [p for p in sorted_profiles if p.finding_count > 0]

    return [p.ip for p in sorted_profiles]


def _build_risk_assessment(
    risk: float,
    phase: str,
    finding_count: int,
    consec_fail: int,
) -> str:
    """Generate a brief risk assessment text."""
    parts: list[str] = []

    if risk >= 75:
        parts.append(f"CRITICAL: Risk score {risk:.0f}/100 — near kill-switch threshold")
    elif risk >= 40:
        parts.append(f"ELEVATED: Risk score {risk:.0f}/100 — proceed with caution")
    else:
        parts.append(f"LOW: Risk score {risk:.0f}/100 — safe to continue discovery")

    if consec_fail > 0:
        parts.append(f"WARNING: {consec_fail} consecutive failure(s) — consider approach change")

    if finding_count == 0 and phase not in ("reconnaissance",):
        parts.append("NOTE: No findings yet — broaden scan scope")

    return " | ".join(parts)


def _build_tool_rationale(
    profiles: list[TargetProfile],
    specialist: str,
    approach: str,
    stealth: bool,
) -> str:
    """Explain why the chosen tools were selected."""
    parts: list[str] = []

    target_types = {p.target_type for p in profiles} if profiles else {TARGET_TYPE_UNKNOWN}
    parts.append(f"Target types: {', '.join(sorted(target_types))}")

    if specialist != "general":
        parts.append(f"Specialist: {specialist} — tools optimised for this target class")

    parts.append(f"Approach: {approach}")

    if stealth:
        parts.append("Stealth mode: preferring SYN scans and low-profile tools")

    return " | ".join(parts)
