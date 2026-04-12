"""LangGraph implementation for the Autonomous AI Red Team Agent.

Production-grade StateGraph with:
- Adaptive strategy engine for context-aware tool selection
- Specialist sub-agents (web exploitation vs network pivoting)
- Strategic planner with kill-switch monitoring
- Critic node for self-correction and stuck detection
- Recovery node for graceful degradation after tool failures
- JSON state backup on failures
- Mandatory human approval gates before exploitation
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
from pathlib import Path
from typing import Any

from langchain_core.messages import BaseMessage, HumanMessage, RemoveMessage, SystemMessage
from langchain_ollama import ChatOllama
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import create_react_agent

from src.agent.prompts import build_system_prompt
from src.agent.state import (
    EXTENDED_PHASES,
    KILL_SWITCH_ERROR_THRESHOLD,
    KILL_SWITCH_RISK_THRESHOLD,
    MAX_CONSECUTIVE_FAILURES,
    AgentState,
    ErrorRecord,
    StrategyEntry,
    calculate_risk_score,
    initial_state,
)
from src.agent.strategy import (
    SPECIALIST_NETWORK_TOOLS,
    SPECIALIST_WEB_TOOLS,
    StrategyRecommendation,
    classify_all_targets,
    compute_strategy,
    determine_specialist,
)
from src.config import get_settings
from src.tools import tools as tools_list

# ── Tool classification ──────────────────────────────────────────────────────
ALL_TOOLS = tools_list

RECON_TOOLS = [t for t in ALL_TOOLS if t.name in {
    "ping_sweep", "banner_grab", "nmap_os_detection",
}]

SCANNING_TOOLS = [t for t in ALL_TOOLS if t.name in {
    "nmap_scan", "tcp_syn_scan", "http_get", "http_post", "directory_bruteforce",
}]

EXPLOIT_TOOLS = [t for t in ALL_TOOLS if t.name in {
    "msf_search_exploits", "msf_run_exploit", "msf_list_sessions",
}]

POST_EXPLOIT_TOOLS = [t for t in ALL_TOOLS if t.name in {
    "http_get", "banner_grab", "msf_list_sessions",
}]

# Specialist tool sets (resolved from ALL_TOOLS)
WEB_SPECIALIST_TOOLS = [t for t in ALL_TOOLS if t.name in set(SPECIALIST_WEB_TOOLS)]
NETWORK_SPECIALIST_TOOLS = [t for t in ALL_TOOLS if t.name in set(SPECIALIST_NETWORK_TOOLS)]

# Fallback tools when Metasploit is unavailable
FALLBACK_TOOLS = [t for t in ALL_TOOLS if t.name in {
    "nmap_scan", "tcp_syn_scan", "http_get", "http_post",
    "directory_bruteforce", "banner_grab",
}]

# Tools that require human approval before execution
APPROVAL_REQUIRED_TOOLS = [
    "msf_run_exploit",
]

# Phase → default tool list mapping
PHASE_DEFAULT_TOOLS: dict[str, list[Any]] = {
    "reconnaissance": RECON_TOOLS or ALL_TOOLS,
    "scanning": SCANNING_TOOLS or ALL_TOOLS,
    "exploitation": EXPLOIT_TOOLS or ALL_TOOLS,
    "post_exploitation": POST_EXPLOIT_TOOLS or ALL_TOOLS,
    "triage": ALL_TOOLS,
    "remediation": ALL_TOOLS,
}

# ── State backup directory ───────────────────────────────────────────────────
STATE_BACKUP_DIR = Path("logs/state_backups")


# ── JSON state backup ────────────────────────────────────────────────────────

def _backup_state_to_json(state: AgentState, reason: str) -> None:
    """Persist a snapshot of the agent state to JSON for crash recovery.

    Serialises only JSON-safe fields (skips LangChain message objects).
    """
    STATE_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    backup_path = STATE_BACKUP_DIR / f"state_{timestamp}.json"

    safe_state: dict[str, Any] = {}
    skip_keys = {"messages"}
    for key, value in state.items():
        if key not in skip_keys:
            try:
                json.dumps(value)
                safe_state[key] = value
            except (TypeError, ValueError):
                safe_state[key] = str(value)

    safe_state["_backup_reason"] = reason
    safe_state["_backup_timestamp"] = timestamp

    try:
        with backup_path.open("w", encoding="utf-8") as f:
            json.dump(safe_state, f, indent=2, default=str)
    except OSError:
        pass


# ── Helper: build a phase-scoped ReAct sub-agent ─────────────────────────────

def _make_phase_agent(
    model: Any,
    tools: list[Any],
    phase_name: str,
) -> Any:
    """Create a ReAct agent scoped to a specific kill-chain phase."""

    def state_modifier(state: AgentState) -> list[BaseMessage]:
        prompt = build_system_prompt(
            dict(state),
            max_steps=state.get("max_steps", 50),
        )
        return [SystemMessage(content=prompt)]

    return create_react_agent(
        model=model,
        tools=tools,
        state_modifier=state_modifier,
    )


def _resolve_tools_by_name(tool_names: list[str]) -> list[Any]:
    """Resolve tool name strings to actual tool objects from ALL_TOOLS."""
    name_set = set(tool_names)
    resolved = [t for t in ALL_TOOLS if t.name in name_set]
    return resolved if resolved else ALL_TOOLS


# ══════════════════════════════════════════════════════════════════════════════
# NODE FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def adaptive_strategy_node(state: AgentState) -> dict[str, Any]:
    """Run the adaptive strategy engine before each phase.

    Analyses target classification, findings, risk, and stealth requirements
    to produce a StrategyRecommendation. The recommendation is stored in state
    for the phase agent to consume via the system prompt.
    """
    recommendation = compute_strategy(dict(state))

    return {
        "plan": (
            f"[Strategy] Phase: {recommendation.phase} | "
            f"Approach: {recommendation.approach} | "
            f"Specialist: {recommendation.specialist} | "
            f"Focus: {', '.join(recommendation.primary_targets[:3]) or 'all'} | "
            f"Tools: {', '.join(recommendation.recommended_tools[:5])}"
        ),
    }


def strategic_planner_node(state: AgentState) -> dict[str, Any]:
    """Analyse current state and decide the optimal next phase.

    Also checks kill-switch conditions:
    - risk_score > KILL_SWITCH_RISK_THRESHOLD (unless aggressive mode)
    - total_errors >= KILL_SWITCH_ERROR_THRESHOLD
    - consecutive_failures >= MAX_CONSECUTIVE_FAILURES * 2

    This node does NOT call the LLM — deterministic heuristics only.
    """
    phase = state.get("current_phase", "reconnaissance")
    findings = state.get("findings", [])
    discovered = state.get("discovered_targets", [])
    sessions = state.get("active_sessions", {})
    step = state.get("step_count", 0)
    max_steps = state.get("max_steps", 50)
    aggression = state.get("aggression_level", "medium")
    total_errors = state.get("total_errors", 0)
    consec_fail = state.get("consecutive_failures", 0)

    risk = calculate_risk_score(findings)

    # ── Kill-switch checks ───────────────────────────────────────────────
    kill_switch = False
    kill_reason = ""

    if total_errors >= KILL_SWITCH_ERROR_THRESHOLD:
        kill_switch = True
        kill_reason = (
            f"Total errors ({total_errors}) exceeded threshold "
            f"({KILL_SWITCH_ERROR_THRESHOLD}). Emergency shutdown."
        )
    elif consec_fail >= MAX_CONSECUTIVE_FAILURES * 2:
        kill_switch = True
        kill_reason = (
            f"Consecutive failures ({consec_fail}) indicate systemic issue. "
            "Emergency shutdown."
        )
    elif risk > KILL_SWITCH_RISK_THRESHOLD and aggression != "high":
        kill_switch = True
        kill_reason = (
            f"Risk score ({risk:.0f}) exceeded safe threshold "
            f"({KILL_SWITCH_RISK_THRESHOLD}). Halting to prevent damage."
        )

    if kill_switch:
        _backup_state_to_json(state, f"kill_switch: {kill_reason}")
        entry = StrategyEntry(
            phase=phase,
            decision="KILL SWITCH → reporting",
            reasoning=kill_reason,
            timestamp=dt.datetime.now(dt.UTC).isoformat(),
            risk_score_at_time=risk,
        )
        history = list(state.get("strategy_history", []))
        history.append(entry.to_dict())

        return {
            "current_phase": "reporting",
            "risk_score": risk,
            "strategy_history": history,
            "step_count": step + 1,
            "kill_switch_triggered": True,
            "kill_switch_reason": kill_reason,
        }

    # ── Standard phase routing ───────────────────────────────────────────
    next_phase = phase
    reasoning = ""

    if step >= max_steps:
        next_phase = "reporting"
        reasoning = f"Step limit reached ({step}/{max_steps}). Forcing report."

    elif phase == "reconnaissance":
        if discovered:
            next_phase = "scanning"
            reasoning = (
                f"Discovered {len(discovered)} target(s). "
                "Moving to scanning to enumerate services."
            )
        else:
            reasoning = "Still discovering hosts. Continuing reconnaissance."

    elif phase == "scanning":
        critical_or_high = [
            f for f in findings if f.get("severity") in ("critical", "high")
        ]
        if critical_or_high and aggression != "low":
            next_phase = "exploitation"
            reasoning = (
                f"Found {len(critical_or_high)} critical/high findings. "
                "Escalating to exploitation."
            )
        elif findings:
            if aggression == "low":
                next_phase = "triage"
                reasoning = (
                    "Low aggression mode. Skipping exploitation, moving to triage."
                )
            else:
                reasoning = "Findings present but no critical/high. Continuing scanning."
        else:
            reasoning = "No findings yet. Continuing scanning."

    elif phase == "exploitation":
        if sessions:
            next_phase = "post_exploitation"
            reasoning = (
                f"Obtained {len(sessions)} active session(s). "
                "Moving to post-exploitation."
            )
        elif risk >= 75:
            next_phase = "post_exploitation"
            reasoning = "Risk score ≥ 75 with exploitation attempts. Moving on."
        else:
            reasoning = "No sessions obtained yet. Continuing exploitation attempts."

    elif phase == "post_exploitation":
        next_phase = "triage"
        reasoning = "Post-exploitation complete. Moving to triage."

    elif phase == "triage":
        next_phase = "remediation"
        reasoning = "Triage complete. Generating remediation advice."

    elif phase == "remediation":
        next_phase = "reporting"
        reasoning = "Remediation advice generated. Producing final report."

    # ── Record strategy ──────────────────────────────────────────────────
    entry = StrategyEntry(
        phase=phase,
        decision=f"transition → {next_phase}" if next_phase != phase else "stay",
        reasoning=reasoning,
        timestamp=dt.datetime.now(dt.UTC).isoformat(),
        risk_score_at_time=risk,
    )

    history = list(state.get("strategy_history", []))
    history.append(entry.to_dict())

    updates: dict[str, Any] = {
        "current_phase": next_phase,
        "risk_score": risk,
        "strategy_history": history,
        "step_count": step + 1,
    }

    if next_phase != phase:
        updates["last_successful_phase"] = phase

    return updates


def critic_node(state: AgentState) -> dict[str, Any]:
    """Review the agent's recent behaviour and suggest corrections.

    Checks for:
    1. Stuck detection — same phase for too many consecutive planner calls
    2. Failure rate per phase — recommends skipping failing phases
    3. Repetitive actions — detects if the agent keeps using the same tool
    4. Graceful degradation — if exploit tools fail, suggest fallback plan

    This node is deterministic and fast (no LLM calls).
    """
    phase = state.get("current_phase", "reconnaissance")
    strategy_history = state.get("strategy_history", [])
    error_log = state.get("error_log", [])
    phase_failures = dict(state.get("phase_failures", {}))
    consec_fail = state.get("consecutive_failures", 0)
    findings = state.get("findings", [])

    feedback_items: list[dict[str, Any]] = []
    now = dt.datetime.now(dt.UTC).isoformat()

    # ── Check 1: Stuck detection ─────────────────────────────────────────
    if len(strategy_history) >= 3:
        last_3 = strategy_history[-3:]
        all_stay = all(
            e.get("decision") == "stay" and e.get("phase") == phase
            for e in last_3
        )
        if all_stay:
            feedback_items.append({
                "issue": f"Stuck in '{phase}' for 3+ iterations without progress",
                "suggestion": "Consider changing approach or advancing to next phase",
                "severity": "warning",
                "timestamp": now,
            })

    # ── Check 2: Phase failure rate ──────────────────────────────────────
    phase_fail_count = phase_failures.get(phase, 0)
    if phase_fail_count >= MAX_CONSECUTIVE_FAILURES:
        feedback_items.append({
            "issue": f"Phase '{phase}' has failed {phase_fail_count} times",
            "suggestion": (
                "Recommending phase skip. If exploitation tools fail, "
                "fall back to nmap + http scanning."
            ),
            "severity": "critical",
            "timestamp": now,
        })

    # ── Check 3: Consecutive failure escalation ──────────────────────────
    if consec_fail >= MAX_CONSECUTIVE_FAILURES:
        feedback_items.append({
            "issue": f"{consec_fail} consecutive failures detected",
            "suggestion": (
                "Agent may need a different approach. "
                "Consider reducing aggression or switching tools."
            ),
            "severity": "warning",
            "timestamp": now,
        })

    # ── Check 4: MSF failure → suggest fallback ──────────────────────────
    msf_errors = [
        e for e in error_log
        if e.get("tool_name", "").startswith("msf_")
    ]
    if len(msf_errors) >= 2:
        feedback_items.append({
            "issue": f"Metasploit tools have failed {len(msf_errors)} times",
            "suggestion": (
                "Metasploit may be unreachable. Falling back to manual "
                "nmap + HTTP tools for continued assessment."
            ),
            "severity": "critical",
            "timestamp": now,
        })

    # ── Check 5: Zero findings stagnation ────────────────────────────────
    if not findings and state.get("step_count", 0) > 10:
        feedback_items.append({
            "issue": "No findings after 10+ steps",
            "suggestion": "Broaden scan scope or verify targets are reachable",
            "severity": "warning",
            "timestamp": now,
        })

    # ── Build return ─────────────────────────────────────────────────────
    existing_feedback = list(state.get("critic_feedback", []))
    existing_feedback.extend(feedback_items)

    updates: dict[str, Any] = {
        "critic_feedback": existing_feedback,
    }

    # Auto-skip failing phase if critical feedback exists
    critical_feedback = [f for f in feedback_items if f.get("severity") == "critical"]
    if critical_feedback and phase_fail_count >= MAX_CONSECUTIVE_FAILURES:
        phase_idx = (
            EXTENDED_PHASES.index(phase)
            if phase in EXTENDED_PHASES
            else 0
        )
        if phase_idx + 1 < len(EXTENDED_PHASES):
            next_phase = EXTENDED_PHASES[phase_idx + 1]
            updates["current_phase"] = next_phase
            updates["consecutive_failures"] = 0

    return updates


def recovery_node(state: AgentState) -> dict[str, Any]:
    """Handle error state and attempt graceful recovery.

    Performs:
    1. State backup to JSON
    2. Error categorisation
    3. Fallback tool recommendation
    """
    phase = state.get("current_phase", "reconnaissance")
    error_log = list(state.get("error_log", []))
    total_errors = state.get("total_errors", 0)

    _backup_state_to_json(state, f"recovery_node in phase={phase}")

    recovery_action = "continue"
    if error_log:
        latest_error = error_log[-1]
        tool = latest_error.get("tool_name", "")

        if tool.startswith("msf_"):
            recovery_action = "fallback_to_manual"
        elif tool in ("ping_sweep", "tcp_syn_scan"):
            recovery_action = "retry_with_delay"
        else:
            recovery_action = "skip_and_continue"

    return {
        "plan": f"[Recovery] Action: {recovery_action} | "
                f"Errors: {total_errors} | Phase: {phase}",
    }


def memory_manager_node(state: AgentState) -> dict[str, Any]:
    """Summarize old chat history and keep context window small."""
    messages = state.get("messages", [])
    updates: dict[str, Any] = {}
    
    # If the message history gets too long (e.g. > 15 messages), prune the oldest ones.
    if len(messages) > 15:
        # Keep the system message, objective (first human message) and the last 10 messages.
        messages_to_remove = messages[1:-10]
        remove_requests = [RemoveMessage(id=m.id) for m in messages_to_remove if hasattr(m, "id") and m.id]
        if remove_requests:
            updates["messages"] = remove_requests
            
    return updates


def adaptive_learning_node(state: AgentState) -> dict[str, Any]:
    """Self-critique after an engagement to suggest improvements."""
    from src.config import get_settings
    from langchain_ollama import ChatOllama
    
    settings = get_settings()
    model = ChatOllama(
        base_url=settings.llm.ollama_base_url,
        model=settings.llm.ollama_model,
        temperature=0.2,
    )
    
    findings = state.get("findings", [])
    errors = state.get("total_errors", 0)
    risk = state.get("risk_score", 0)
    
    prompt = (
        f"You are a Red Team Agent evaluating your own performance in a simulated engagement.\n"
        f"Findings count: {len(findings)}\n"
        f"Errors encountered: {errors}\n"
        f"Final Risk Score: {risk}\n"
        f"Provide a brief self-critique (3 sentences max) evaluating what went well and what you can improve "
        f"in terms of efficiency, tool usage, or stealth in future engagements."
    )
    
    msg = model.invoke(prompt)
    
    critique_text = msg.content if msg and hasattr(msg, "content") else str(msg)
    
    return {
        "plan": f"[Adaptive Learning] {critique_text}",
        "messages": [SystemMessage(content=f"Self-critique complete: {critique_text}")],
    }


# ══════════════════════════════════════════════════════════════════════════════
# GRAPH BUILDER
# ══════════════════════════════════════════════════════════════════════════════

def build_redteam_graph(model: Any) -> Any:
    """Build the production-grade red teaming agent graph.

    Graph topology::

        START
          → strategic_planner
          → (kill-switch? → END)
          → critic → (needs recovery?)
              → recovery → strategic_planner
              → adaptive_strategy → route_to_phase
                  → recon_phase / scanning_phase / ...
                  → web_specialist / network_specialist
          → strategic_planner  (loop)
    """

    # ── Create phase-specific sub-agents ─────────────────────────────────
    recon_agent = _make_phase_agent(model, RECON_TOOLS or ALL_TOOLS, "reconnaissance")
    scanning_agent = _make_phase_agent(model, SCANNING_TOOLS or ALL_TOOLS, "scanning")
    exploit_agent = _make_phase_agent(model, EXPLOIT_TOOLS or ALL_TOOLS, "exploitation")
    post_exploit_agent = _make_phase_agent(model, POST_EXPLOIT_TOOLS or ALL_TOOLS, "post_exploitation")
    triage_agent = _make_phase_agent(model, ALL_TOOLS, "triage")
    remediation_agent = _make_phase_agent(model, ALL_TOOLS, "remediation")

    # ── Specialist sub-agents ────────────────────────────────────────────
    web_specialist_agent = _make_phase_agent(model, WEB_SPECIALIST_TOOLS or ALL_TOOLS, "web_specialist")
    network_specialist_agent = _make_phase_agent(model, NETWORK_SPECIALIST_TOOLS or ALL_TOOLS, "network_specialist")

    # ── Build the graph ──────────────────────────────────────────────────
    builder = StateGraph(AgentState)

    # Core nodes
    builder.add_node("memory_manager", memory_manager_node)
    builder.add_node("strategic_planner", strategic_planner_node)
    builder.add_node("adaptive_strategy", adaptive_strategy_node)
    builder.add_node("critic", critic_node)
    builder.add_node("recovery", recovery_node)
    builder.add_node("adaptive_learning", adaptive_learning_node)

    # Phase nodes
    builder.add_node("recon_phase", recon_agent)
    builder.add_node("scanning_phase", scanning_agent)
    builder.add_node("exploitation_phase", exploit_agent)
    builder.add_node("post_exploitation_phase", post_exploit_agent)
    builder.add_node("triage_phase", triage_agent)
    builder.add_node("remediation_phase", remediation_agent)

    # Specialist nodes
    builder.add_node("web_specialist", web_specialist_agent)
    builder.add_node("network_specialist", network_specialist_agent)

    # ── Entry ────────────────────────────────────────────────────────────
    builder.add_edge(START, "memory_manager")
    builder.add_edge("memory_manager", "strategic_planner")

    # ── Planner → Critic or END ──────────────────────────────────────────
    def planner_to_critic_or_end(state: AgentState) -> str:
        phase = state.get("current_phase", "reconnaissance")
        step = state.get("step_count", 0)
        max_steps = state.get("max_steps", 50)
        killed = state.get("kill_switch_triggered", False)

        if killed or phase == "reporting" or step >= max_steps:
            return "adaptive_learning"
        return "critic"

    builder.add_conditional_edges(
        "strategic_planner",
        planner_to_critic_or_end,
        {"critic": "critic", "adaptive_learning": "adaptive_learning"},
    )
    
    # Adaptive learning is the true end
    builder.add_edge("adaptive_learning", END)

    # ── Critic → Recovery or Adaptive Strategy ───────────────────────────
    def critic_to_recovery_or_strategy(state: AgentState) -> str:
        consec_fail = state.get("consecutive_failures", 0)
        critic_fb = state.get("critic_feedback", [])

        needs_recovery = False
        if critic_fb:
            recent_critical = [
                f for f in critic_fb[-3:]
                if f.get("severity") == "critical"
            ]
            if recent_critical and consec_fail >= MAX_CONSECUTIVE_FAILURES:
                needs_recovery = True

        if needs_recovery:
            return "recovery"
        return "adaptive_strategy"

    builder.add_conditional_edges(
        "critic",
        critic_to_recovery_or_strategy,
        {"recovery": "recovery", "adaptive_strategy": "adaptive_strategy"},
    )

    # ── Recovery → back to planner ───────────────────────────────────────
    builder.add_edge("recovery", "strategic_planner")

    # ── Adaptive Strategy → Phase routing ────────────────────────────────
    def route_after_strategy(state: AgentState) -> str:
        """Route to phase node or specialist based on strategy recommendation."""
        phase = state.get("current_phase", "reconnaissance")
        plan = state.get("plan", "")

        # Check if strategy recommended a specialist
        if "web_specialist" in plan and phase in ("exploitation", "scanning"):
            return "web_specialist"
        elif "network_specialist" in plan and phase in ("exploitation", "scanning"):
            return "network_specialist"

        phase_map = {
            "reconnaissance": "recon_phase",
            "scanning": "scanning_phase",
            "exploitation": "exploitation_phase",
            "post_exploitation": "post_exploitation_phase",
            "triage": "triage_phase",
            "remediation": "remediation_phase",
        }
        return phase_map.get(phase, END)

    builder.add_conditional_edges(
        "adaptive_strategy",
        route_after_strategy,
        {
            "recon_phase": "recon_phase",
            "scanning_phase": "scanning_phase",
            "exploitation_phase": "exploitation_phase",
            "post_exploitation_phase": "post_exploitation_phase",
            "triage_phase": "triage_phase",
            "remediation_phase": "remediation_phase",
            "web_specialist": "web_specialist",
            "network_specialist": "network_specialist",
            END: END,
        },
    )

    # ── All phase & specialist nodes loop back to the planner ────────────
    for node in [
        "recon_phase",
        "scanning_phase",
        "exploitation_phase",
        "post_exploitation_phase",
        "triage_phase",
        "remediation_phase",
        "web_specialist",
        "network_specialist",
    ]:
        builder.add_edge(node, "strategic_planner")

    # ── Compile ──────────────────────────────────────────────────────────
    # Ensure database path exists for SqliteSaver
    Path("logs").mkdir(exist_ok=True)
    sqlite_path = "logs/checkpoints.db"
    conn = sqlite3.connect(sqlite_path, check_same_thread=False)

    return builder.compile(
        checkpointer=SqliteSaver(conn),
        interrupt_before=["exploitation_phase"],
    )


# ══════════════════════════════════════════════════════════════════════════════
# ENGAGEMENT MODES
# ══════════════════════════════════════════════════════════════════════════════

MODE_PRESETS: dict[str, dict[str, Any]] = {
    "dynamic": {
        "aggression_level": "medium",
        "stealth_mode": False,
        "max_steps": 50,
    },
    "safe": {
        "aggression_level": "low",
        "stealth_mode": True,
        "max_steps": 30,
    },
    "aggressive": {
        "aggression_level": "high",
        "stealth_mode": False,
        "max_steps": 75,
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# HIGH-LEVEL ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def run_redteam_agent(
    objective: str,
    targets: list[str],
    max_steps: int = 50,
    thread_id: str = "redteam-session-1",
    aggression_level: str = "medium",
    stealth_mode: bool = False,
    mode: str | None = None,
    verbose: bool = False,
) -> Any:
    """Execute the red team agent for a given objective."""
    settings = get_settings()

    if mode and mode in MODE_PRESETS:
        preset = MODE_PRESETS[mode]
        aggression_level = preset["aggression_level"]
        stealth_mode = preset["stealth_mode"]
        max_steps = preset["max_steps"]

    model = ChatOllama(
        base_url=settings.llm.ollama_base_url,
        model=settings.llm.ollama_model,
        temperature=settings.llm.temperature,
    )

    state = initial_state(
        targets=targets,
        max_steps=max_steps,
        allowed_subnet=settings.safety.allowed_target_subnet,
        aggression_level=aggression_level,
        stealth_mode=stealth_mode,
    )
    state["messages"] = [HumanMessage(content=objective)]

    config = {"configurable": {"thread_id": thread_id}}
    graph = build_redteam_graph(model=model)

    mode_label = mode or "custom"
    print(f"\n🚀 Engagement started: {objective}")
    print(f"   Targets: {targets}")
    print(f"   Mode: {mode_label} | Aggression: {aggression_level} | "
          f"Stealth: {stealth_mode}")
    print(f"   Max steps: {max_steps} | Kill-switch: risk>{KILL_SWITCH_RISK_THRESHOLD} "
          f"or errors≥{KILL_SWITCH_ERROR_THRESHOLD}\n")

    import time
    start_time = time.time()
    session_timeout_sec = 3600  # 1 hour max session timeout

    for chunk in graph.stream(state, config, stream_mode="updates"):
        # Rate limit between node executions (prevent flooding LLM and target)
        time.sleep(1.0)
        
        # Check session timeout
        if time.time() - start_time > session_timeout_sec:
            print("⏳ Session timeout reached! Sending kill signal.")
            # Trigger kill switch via a manual state update if possible, or just break
            break
            
        for node_name, node_output in chunk.items():
            if node_name == "strategic_planner":
                history = node_output.get("strategy_history", [])
                if history:
                    latest = history[-1]
                    decision = latest.get("decision", "?")
                    risk_val = latest.get("risk_score_at_time", 0)
                    reason = latest.get("reasoning", "")
                    emoji = "🛑" if "KILL" in decision else "🧠"
                    print(f"  {emoji} Planner: {decision} "
                          f"(risk={risk_val:.0f}) — {reason}")
            elif node_name == "adaptive_strategy":
                plan = node_output.get("plan", "")
                if plan:
                    print(f"  🎯 {plan}")
            elif node_name == "critic":
                fb = node_output.get("critic_feedback", [])
                if fb:
                    latest_fb = fb[-1] if fb else {}
                    if latest_fb:
                        print(f"  🔍 Critic: [{latest_fb.get('severity', '?')}] "
                              f"{latest_fb.get('issue', '')}")
            elif node_name == "recovery":
                plan = node_output.get("plan", "")
                print(f"  🔧 Recovery: {plan}")
            elif node_name == "adaptive_learning":
                plan = node_output.get("plan", "")
                if plan:
                    print(f"  🧑‍🏫 {plan}")
            elif node_name in ("web_specialist", "network_specialist"):
                msgs = node_output.get("messages", [])
                if msgs:
                    last = msgs[-1]
                    if hasattr(last, "content") and last.content:
                        preview = last.content if verbose else last.content[:300] + "..."
                        print(f"  🔬 [{node_name}]: {preview}")
            else:
                msgs = node_output.get("messages", [])
                if msgs:
                    last = msgs[-1]
                    if hasattr(last, "content") and last.content:
                        preview = last.content if verbose else last.content[:500] + "..."
                        print(f"  [{node_name}]: {preview}")

    final = graph.get_state(config)

    if hasattr(final, "values"):
        _backup_state_to_json(final.values, "engagement_complete")

    return final


# Backward-compatible alias
run_agent = run_redteam_agent
