"""Dynamic Test Suite — 8 realistic engagement scenarios.

Each scenario simulates a full engagement lifecycle by constructing a
detailed initial state, running the deterministic planner/critic/strategy
nodes through the kill-chain stages, and producing a structured
ScenarioResult with 5-axis scoring:

    1. Success Rate      — findings quality, phase completion
    2. Safety Compliance — errors, kill-switch, scope adherence
    3. Efficiency        — steps-to-findings ratio, error rate
    4. Risk Management   — risk trajectory, intervention quality
    5. Phase Smoothness  — transition count vs stuck iterations

All scenarios are self-contained:  NO Ollama, NO live network.
They exercise only the deterministic brain of the agent (planner,
critic, strategy engine, recovery node) to validate that the
decision-making logic behaves correctly in realistic situations.

Run:
    python -m pytest tests/dynamic_test_suite.py -v
    python -m tests.dynamic_test_suite          # standalone JSON report
"""

from __future__ import annotations

import json
import datetime as dt
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import pytest

from src.agent.graph import (
    adaptive_strategy_node,
    critic_node,
    recovery_node,
    strategic_planner_node,
    MODE_PRESETS,
)
from src.agent.state import (
    EXTENDED_PHASES,
    DiscoveredTarget,
    ErrorRecord,
    Finding,
    StrategyEntry,
    calculate_engagement_success,
    calculate_risk_score,
    initial_state,
)
from src.agent.strategy import (
    StrategyRecommendation,
    classify_target,
    compute_strategy,
    determine_specialist,
)


# ══════════════════════════════════════════════════════════════════════════════
# Scenario Result — structured report per scenario
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScenarioResult:
    """Structured result of a single test scenario."""

    scenario_id: int
    scenario_name: str
    mode: str
    targets: list[str]

    # Trace
    execution_trace: list[dict[str, Any]] = field(default_factory=list)

    # Final state snapshot
    final_phase: str = "reconnaissance"
    total_steps: int = 0
    total_findings: int = 0
    total_errors: int = 0
    risk_score: float = 0.0
    kill_switch_triggered: bool = False
    kill_switch_reason: str = ""
    critic_interventions: int = 0
    strategy_decisions: int = 0

    # Scores (0–100)
    success_rate: float = 0.0
    safety_compliance: float = 0.0
    efficiency: float = 0.0
    risk_management: float = 0.0
    phase_smoothness: float = 0.0
    overall: float = 0.0

    passed: bool = True
    failure_reason: str = ""

    def compute_scores(self, state: dict[str, Any]) -> None:
        """Compute all 5-axis scores from final state."""
        findings = state.get("findings", [])
        strategy = state.get("strategy_history", [])
        errors = state.get("total_errors", 0)
        consec = state.get("consecutive_failures", 0)
        phase = state.get("current_phase", "reconnaissance")
        step = state.get("step_count", 0)
        max_steps = state.get("max_steps", 50)

        self.final_phase = phase
        self.total_steps = step
        self.total_findings = len(findings)
        self.total_errors = errors
        self.risk_score = state.get("risk_score", 0.0)
        self.kill_switch_triggered = state.get("kill_switch_triggered", False)
        self.kill_switch_reason = state.get("kill_switch_reason", "")
        self.critic_interventions = len(state.get("critic_feedback", []))
        self.strategy_decisions = len(strategy)

        # 1. Success Rate
        phase_idx = EXTENDED_PHASES.index(phase) if phase in EXTENDED_PHASES else 0
        phase_pct = ((phase_idx + 1) / len(EXTENDED_PHASES)) * 50
        finding_pct = min(len(findings) * 10, 50)
        self.success_rate = round(min(phase_pct + finding_pct, 100.0), 1)

        # 2. Safety Compliance
        safety = 100.0
        if self.kill_switch_triggered:
            safety -= 25
        safety -= min(errors * 5, 40)
        safety -= min(consec * 3, 15)
        if state.get("aggression_level") == "low":
            safety = min(safety + 10, 100)
        self.safety_compliance = round(max(safety, 0.0), 1)

        # 3. Efficiency
        if step > 0:
            findings_per_step = len(findings) / step
            eff = min(findings_per_step * 150, 60.0)
            error_rate = errors / step
            eff += max(40 - error_rate * 100, 0)
        else:
            eff = 0.0
        self.efficiency = round(min(eff, 100.0), 1)

        # 4. Risk Management
        rm = 100.0
        if self.risk_score > 80 and not self.kill_switch_triggered:
            rm -= 30  # Dangerously high risk without safety action
        if self.kill_switch_triggered:
            rm -= 10  # Had to resort to kill-switch (but at least it worked)
        rm -= min(consec * 5, 25)
        if self.critic_interventions > 0:
            rm = min(rm + 10, 100)  # Bonus for self-awareness
        self.risk_management = round(max(rm, 0.0), 1)

        # 5. Phase Smoothness (transitions vs total planner calls)
        transitions = sum(1 for s in strategy if "transition" in s.get("decision", ""))
        stays = sum(1 for s in strategy if s.get("decision") == "stay")
        total_decisions = transitions + stays
        if total_decisions > 0:
            smoothness = (transitions / total_decisions) * 100
        else:
            smoothness = 50.0
        self.phase_smoothness = round(min(smoothness, 100.0), 1)

        # Overall
        self.overall = round(
            self.success_rate * 0.25
            + self.safety_compliance * 0.25
            + self.efficiency * 0.20
            + self.risk_management * 0.15
            + self.phase_smoothness * 0.15,
            1,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _trace(trace_log: list[dict[str, Any]], node: str, output: dict[str, Any]) -> None:
    """Append a trace entry."""
    trace_log.append({
        "timestamp": dt.datetime.now(dt.UTC).isoformat(),
        "node": node,
        "phase": output.get("current_phase", "?"),
        "decision": (output.get("strategy_history", [{}])[-1].get("decision", "")
                     if output.get("strategy_history") else ""),
        "risk": output.get("risk_score", 0),
        "plan": output.get("plan", "")[:120],
    })


def _run_planner_loop(state: dict[str, Any], max_loops: int = 20) -> dict[str, Any]:
    """Run planner → critic → strategy in a loop until reporting or max_loops."""
    trace: list[dict[str, Any]] = []

    for _ in range(max_loops):
        # 1. Planner
        updates = strategic_planner_node(state)
        state.update(updates)
        _trace(trace, "planner", updates)

        if state.get("current_phase") == "reporting" or state.get("kill_switch_triggered"):
            break

        # 2. Critic
        critic_updates = critic_node(state)
        state.update(critic_updates)
        if critic_updates.get("critic_feedback"):
            _trace(trace, "critic", critic_updates)

        # 3. Recovery if needed
        consec = state.get("consecutive_failures", 0)
        from src.agent.state import MAX_CONSECUTIVE_FAILURES
        critical_fb = [f for f in state.get("critic_feedback", [])[-3:]
                       if f.get("severity") == "critical"]
        if critical_fb and consec >= MAX_CONSECUTIVE_FAILURES:
            rec = recovery_node(state)
            state.update(rec)
            _trace(trace, "recovery", rec)

        # 4. Strategy
        strat = adaptive_strategy_node(state)
        state.update(strat)
        _trace(trace, "strategy", strat)

        if state.get("current_phase") == "reporting":
            break

    state["_trace"] = trace
    return state


# ══════════════════════════════════════════════════════════════════════════════
# SCENARIO DEFINITIONS
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def reset_settings():
    """Reset the settings singleton before each test."""
    from src import config
    config._settings = None
    yield
    config._settings = None


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 1: Pure Recon on DVWA (Safe Mode)
# ─────────────────────────────────────────────────────────────────────────────
class TestScenario01_SafeReconDVWA:
    """Safe mode, single web target. Should only do recon → scan → triage."""

    SCENARIO_ID = 1
    SCENARIO_NAME = "Pure Recon — DVWA (Safe Mode)"
    MODE = "safe"

    def _build_state(self) -> dict[str, Any]:
        preset = MODE_PRESETS["safe"]
        state = initial_state(
            targets=["172.28.0.10"],
            max_steps=preset["max_steps"],
            aggression_level=preset["aggression_level"],
            stealth_mode=preset["stealth_mode"],
        )
        return state

    def test_never_reaches_exploitation(self) -> None:
        state = self._build_state()
        state["discovered_targets"] = [
            DiscoveredTarget(ip="172.28.0.10", open_ports=[80, 443], services=["http"]).to_dict(),
        ]
        state["findings"] = [
            Finding(target="172.28.0.10", vulnerability="SQLi", severity="critical").to_dict(),
        ]
        state = _run_planner_loop(state)
        phases_visited = {e.get("phase") for e in state.get("_trace", [])}
        assert "exploitation" not in phases_visited

    def test_reaches_reporting(self) -> None:
        state = self._build_state()
        state["discovered_targets"] = [
            DiscoveredTarget(ip="172.28.0.10", open_ports=[80]).to_dict(),
        ]
        state["findings"] = [
            Finding(target="172.28.0.10", vulnerability="XSS", severity="medium").to_dict(),
        ]
        state = _run_planner_loop(state)
        assert state["current_phase"] == "reporting"

    def test_stealth_strategy_used(self) -> None:
        state = self._build_state()
        state["current_phase"] = "scanning"
        state["discovered_targets"] = [
            {"ip": "172.28.0.10", "open_ports": [80], "services": ["http"]},
        ]
        rec = compute_strategy(state)
        assert rec.approach == "stealth_scan"
        assert "tcp_syn_scan" in rec.recommended_tools

    def test_safety_score_high(self) -> None:
        state = self._build_state()
        state["discovered_targets"] = [
            DiscoveredTarget(ip="172.28.0.10", open_ports=[80]).to_dict(),
        ]
        state["findings"] = [
            Finding(target="172.28.0.10", vulnerability="Info", severity="info").to_dict(),
        ]
        state = _run_planner_loop(state)
        result = ScenarioResult(self.SCENARIO_ID, self.SCENARIO_NAME, self.MODE, ["172.28.0.10"])
        result.compute_scores(state)
        assert result.safety_compliance >= 90


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 2: Full Scan on DVWA (Dynamic Mode)
# ─────────────────────────────────────────────────────────────────────────────
class TestScenario02_FullScanDVWA:
    """Dynamic mode, DVWA. Should traverse full kill-chain with human gates."""

    SCENARIO_ID = 2
    SCENARIO_NAME = "Full Scan — DVWA (Dynamic)"

    def _build_state(self) -> dict[str, Any]:
        return initial_state(targets=["172.28.0.10"], aggression_level="medium")

    def test_full_lifecycle_reaches_reporting(self) -> None:
        state = self._build_state()
        state["discovered_targets"] = [
            DiscoveredTarget(ip="172.28.0.10", open_ports=[80, 443, 8080]).to_dict(),
        ]
        state["findings"] = [
            Finding(target="172.28.0.10", vulnerability="SQLi", severity="critical").to_dict(),
            Finding(target="172.28.0.10", vulnerability="XSS", severity="high").to_dict(),
        ]
        state["active_sessions"] = {"1": {"target": "172.28.0.10"}}
        state = _run_planner_loop(state)
        assert state["current_phase"] == "reporting"

    def test_web_specialist_selected(self) -> None:
        state = self._build_state()
        state["current_phase"] = "scanning"
        state["discovered_targets"] = [
            {"ip": "172.28.0.10", "open_ports": [80, 443, 8080], "services": ["http", "https"]},
        ]
        rec = compute_strategy(state)
        assert rec.specialist == "web_specialist"

    def test_strategy_history_complete(self) -> None:
        state = self._build_state()
        state["discovered_targets"] = [
            DiscoveredTarget(ip="172.28.0.10", open_ports=[80]).to_dict(),
        ]
        state["findings"] = [
            Finding(target="172.28.0.10", vulnerability="RCE", severity="critical").to_dict(),
        ]
        state["active_sessions"] = {"1": {"target": "172.28.0.10"}}
        state = _run_planner_loop(state)
        assert len(state["strategy_history"]) >= 5  # recon→scan→exploit→post→triage→remed→report


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 3: Multi-Target Assessment (DVWA + Struts)
# ─────────────────────────────────────────────────────────────────────────────
class TestScenario03_MultiTarget:
    """Dynamic mode, two web targets with distinct service profiles."""

    SCENARIO_ID = 3
    SCENARIO_NAME = "Multi-Target — DVWA + Struts (Dynamic)"

    def _build_state(self) -> dict[str, Any]:
        return initial_state(targets=["172.28.0.10", "172.28.0.12"])

    def test_both_targets_profiled(self) -> None:
        state = self._build_state()
        state["discovered_targets"] = [
            {"ip": "172.28.0.10", "open_ports": [80, 443], "services": ["apache"]},
            {"ip": "172.28.0.12", "open_ports": [8080], "services": ["apache"]},
        ]
        state["current_phase"] = "scanning"
        rec = compute_strategy(state)
        # Both are web targets
        assert rec.specialist == "web_specialist"
        assert "http_get" in rec.recommended_tools

    def test_risk_reflects_multi_target_findings(self) -> None:
        state = self._build_state()
        state["findings"] = [
            Finding(target="172.28.0.10", vulnerability="SQLi", severity="critical").to_dict(),
            Finding(target="172.28.0.12", vulnerability="RCE", severity="critical").to_dict(),
            Finding(target="172.28.0.12", vulnerability="Struts", severity="high").to_dict(),
        ]
        risk = calculate_risk_score(state["findings"])
        assert risk == 65.0  # 25+25+15

    def test_multi_target_lifecycle(self) -> None:
        state = self._build_state()
        state["discovered_targets"] = [
            DiscoveredTarget(ip="172.28.0.10", open_ports=[80]).to_dict(),
            DiscoveredTarget(ip="172.28.0.12", open_ports=[8080]).to_dict(),
        ]
        state["findings"] = [
            Finding(target="172.28.0.10", vulnerability="SQLi", severity="critical").to_dict(),
            Finding(target="172.28.0.12", vulnerability="RCE", severity="critical").to_dict(),
        ]
        state["active_sessions"] = {"1": {"target": "172.28.0.10"}}
        state = _run_planner_loop(state)
        assert state["current_phase"] == "reporting"

    def test_priority_ranking_correct(self) -> None:
        state = self._build_state()
        state["current_phase"] = "exploitation"
        state["discovered_targets"] = [
            {"ip": "172.28.0.10", "open_ports": [80], "services": []},
            {"ip": "172.28.0.12", "open_ports": [8080], "services": []},
        ]
        state["findings"] = [
            {"target": "172.28.0.12", "severity": "critical"},
        ]
        rec = compute_strategy(state)
        assert rec.primary_targets[0] == "172.28.0.12"  # Higher priority


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 4: High-Stealth Mode (Minimize Noise)
# ─────────────────────────────────────────────────────────────────────────────
class TestScenario04_HighStealth:
    """Stealth + medium aggression. Strategy should prefer SYN scans."""

    SCENARIO_ID = 4
    SCENARIO_NAME = "High-Stealth — Mixed Targets"

    def _build_state(self) -> dict[str, Any]:
        return initial_state(
            targets=["172.28.0.10", "172.28.0.13"],
            stealth_mode=True,
            aggression_level="medium",
        )

    def test_stealth_approach_in_recon(self) -> None:
        state = self._build_state()
        state["current_phase"] = "reconnaissance"
        rec = compute_strategy(state)
        assert rec.approach == "stealth_scan"

    def test_stealth_approach_in_scanning(self) -> None:
        state = self._build_state()
        state["current_phase"] = "scanning"
        state["discovered_targets"] = [
            {"ip": "172.28.0.10", "open_ports": [80], "services": []},
            {"ip": "172.28.0.13", "open_ports": [22], "services": []},
        ]
        rec = compute_strategy(state)
        assert rec.approach == "stealth_scan"
        assert "tcp_syn_scan" in rec.recommended_tools

    def test_exploitation_still_cautious(self) -> None:
        state = self._build_state()
        state["current_phase"] = "exploitation"
        rec = compute_strategy(state)
        assert rec.approach == "cautious_exploit"  # Stealth doesn't affect exploit phase

    def test_network_specialist_for_ssh_target(self) -> None:
        state = self._build_state()
        state["current_phase"] = "scanning"
        state["discovered_targets"] = [
            {"ip": "172.28.0.13", "open_ports": [22], "services": ["openssh"]},
        ]
        rec = compute_strategy(state)
        assert rec.specialist == "network_specialist"


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 5: Recovery from Failed Exploit
# ─────────────────────────────────────────────────────────────────────────────
class TestScenario05_FailedExploitRecovery:
    """Simulate MSF failures triggering critic and recovery."""

    SCENARIO_ID = 5
    SCENARIO_NAME = "Failed Exploit Recovery"

    def _build_state(self) -> dict[str, Any]:
        state = initial_state(targets=["172.28.0.12"])
        state["current_phase"] = "exploitation"
        state["discovered_targets"] = [
            DiscoveredTarget(ip="172.28.0.12", open_ports=[8080]).to_dict(),
        ]
        state["findings"] = [
            Finding(target="172.28.0.12", vulnerability="Struts RCE", severity="critical").to_dict(),
        ]
        return state

    def test_msf_failure_triggers_fallback_tools(self) -> None:
        state = self._build_state()
        state["error_log"] = [
            ErrorRecord(phase="exploitation", tool_name="msf_run_exploit", error_message="timeout").to_dict(),
            ErrorRecord(phase="exploitation", tool_name="msf_search_exploits", error_message="RPC err").to_dict(),
        ]
        rec = compute_strategy(state)
        assert "msf_run_exploit" not in rec.recommended_tools

    def test_critic_flags_msf_failure(self) -> None:
        state = self._build_state()
        state["error_log"] = [
            {"tool_name": "msf_run_exploit", "error_message": "err1"},
            {"tool_name": "msf_search_exploits", "error_message": "err2"},
        ]
        result = critic_node(state)
        fb = result.get("critic_feedback", [])
        assert any("Metasploit" in f.get("issue", "") for f in fb)

    def test_recovery_node_produces_fallback_plan(self) -> None:
        state = self._build_state()
        state["error_log"] = [
            {"tool_name": "msf_run_exploit", "error_message": "Connection refused"},
        ]
        result = recovery_node(state)
        assert "fallback_to_manual" in result["plan"]

    def test_consecutive_failures_force_phase_skip(self) -> None:
        state = self._build_state()
        state["phase_failures"] = {"exploitation": 3}
        state["consecutive_failures"] = 3
        state["error_log"] = [
            {"tool_name": "msf_run_exploit", "error_message": "err"},
            {"tool_name": "msf_run_exploit", "error_message": "err"},
        ]
        result = critic_node(state)
        assert result.get("current_phase") == "post_exploitation"


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 6: Time-Limited Engagement (max 10 steps)
# ─────────────────────────────────────────────────────────────────────────────
class TestScenario06_TimeLimited:
    """Tight step budget — agent must prioritise efficiently."""

    SCENARIO_ID = 6
    SCENARIO_NAME = "Time-Limited Engagement (10 steps)"

    def _build_state(self) -> dict[str, Any]:
        return initial_state(targets=["172.28.0.10"], max_steps=10)

    def test_forces_report_at_limit(self) -> None:
        state = self._build_state()
        state["step_count"] = 10
        state["current_phase"] = "scanning"
        result = strategic_planner_node(state)
        assert result["current_phase"] == "reporting"

    def test_partial_engagement_scores(self) -> None:
        state = self._build_state()
        state["discovered_targets"] = [{"ip": "172.28.0.10"}]
        state["findings"] = [
            Finding(target="172.28.0.10", vulnerability="Open SSH", severity="medium").to_dict(),
        ]
        state = _run_planner_loop(state, max_loops=12)
        result = ScenarioResult(self.SCENARIO_ID, self.SCENARIO_NAME, "dynamic", ["172.28.0.10"])
        result.compute_scores(state)
        assert result.overall > 0
        assert result.total_steps <= 11  # Should not exceed limit + 1

    def test_strategy_works_with_tight_budget(self) -> None:
        state = self._build_state()
        state["current_phase"] = "reconnaissance"
        rec = compute_strategy(state)
        assert len(rec.recommended_tools) > 0

    def test_findings_preserved_on_early_exit(self) -> None:
        state = self._build_state()
        state["step_count"] = 10
        state["findings"] = [
            {"severity": "high", "target": "172.28.0.10"},
            {"severity": "medium", "target": "172.28.0.10"},
        ]
        result = strategic_planner_node(state)
        assert result["risk_score"] == 23.0  # 15+8


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 7: High-Risk Target — Force Critic Intervention
# ─────────────────────────────────────────────────────────────────────────────
class TestScenario07_HighRiskCriticIntervention:
    """Simulate escalating risk that triggers automated safety controls."""

    SCENARIO_ID = 7
    SCENARIO_NAME = "High-Risk Target — Critic Intervention"

    def _build_state(self) -> dict[str, Any]:
        return initial_state(targets=["172.28.0.10"], aggression_level="medium")

    def test_kill_switch_on_high_risk(self) -> None:
        state = self._build_state()
        state["findings"] = [
            Finding(target="172.28.0.10", vulnerability=f"v{i}", severity="critical").to_dict()
            for i in range(5)
        ]
        result = strategic_planner_node(state)
        assert result["kill_switch_triggered"] is True
        assert result["current_phase"] == "reporting"

    def test_critic_detects_stuck_agent(self) -> None:
        state = self._build_state()
        state["current_phase"] = "scanning"
        state["strategy_history"] = [
            {"decision": "stay", "phase": "scanning"},
            {"decision": "stay", "phase": "scanning"},
            {"decision": "stay", "phase": "scanning"},
        ]
        result = critic_node(state)
        fb = result["critic_feedback"]
        assert any("Stuck" in f.get("issue", "") for f in fb)

    def test_stagnation_detected_no_findings(self) -> None:
        state = self._build_state()
        state["step_count"] = 15
        state["findings"] = []
        result = critic_node(state)
        fb = result["critic_feedback"]
        assert any("No findings" in f.get("issue", "") for f in fb)

    def test_aggressive_mode_survives_high_risk(self) -> None:
        state = initial_state(targets=["172.28.0.10"], aggression_level="high")
        state["current_phase"] = "scanning"
        state["findings"] = [
            Finding(target="172.28.0.10", vulnerability=f"v{i}", severity="critical").to_dict()
            for i in range(4)
        ]
        result = strategic_planner_node(state)
        assert result.get("kill_switch_triggered") is not True

    def test_error_threshold_kill_switch(self) -> None:
        state = self._build_state()
        state["total_errors"] = 10
        result = strategic_planner_node(state)
        assert result["kill_switch_triggered"] is True
        assert "Total errors" in result["kill_switch_reason"]


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 8: Complete Engagement with Remediation
# ─────────────────────────────────────────────────────────────────────────────
class TestScenario08_CompleteWithRemediation:
    """Full aggressive engagement — should traverse every phase including remediation."""

    SCENARIO_ID = 8
    SCENARIO_NAME = "Complete Engagement — Aggressive with Remediation"
    MODE = "aggressive"

    def _build_state(self) -> dict[str, Any]:
        preset = MODE_PRESETS["aggressive"]
        state = initial_state(
            targets=["172.28.0.10", "172.28.0.12", "172.28.0.13"],
            max_steps=preset["max_steps"],
            aggression_level=preset["aggression_level"],
            stealth_mode=preset["stealth_mode"],
        )
        return state

    def test_full_aggressive_lifecycle(self) -> None:
        state = self._build_state()
        state["discovered_targets"] = [
            DiscoveredTarget(ip="172.28.0.10", open_ports=[80, 443]).to_dict(),
            DiscoveredTarget(ip="172.28.0.12", open_ports=[8080]).to_dict(),
            DiscoveredTarget(ip="172.28.0.13", open_ports=[22]).to_dict(),
        ]
        state["findings"] = [
            Finding(target="172.28.0.10", vulnerability="SQLi", severity="critical").to_dict(),
            Finding(target="172.28.0.12", vulnerability="RCE", severity="critical").to_dict(),
            Finding(target="172.28.0.13", vulnerability="Weak SSH", severity="high").to_dict(),
        ]
        state["active_sessions"] = {
            "1": {"target": "172.28.0.10"},
            "2": {"target": "172.28.0.12"},
        }
        state = _run_planner_loop(state)
        assert state["current_phase"] == "reporting"

    def test_all_phases_visited(self) -> None:
        state = self._build_state()
        state["discovered_targets"] = [
            DiscoveredTarget(ip="172.28.0.10", open_ports=[80]).to_dict(),
        ]
        state["findings"] = [
            Finding(target="172.28.0.10", vulnerability="SQLi", severity="critical").to_dict(),
        ]
        state["active_sessions"] = {"1": {"target": "172.28.0.10"}}
        state = _run_planner_loop(state)

        # Extract phases from strategy history
        visited_phases = {s.get("phase") for s in state.get("strategy_history", [])}
        assert "reconnaissance" in visited_phases
        assert "scanning" in visited_phases
        assert "exploitation" in visited_phases
        assert "triage" in visited_phases

    def test_engagement_success_score(self) -> None:
        state = self._build_state()
        state["discovered_targets"] = [
            {"ip": "172.28.0.10"}, {"ip": "172.28.0.12"}, {"ip": "172.28.0.13"},
        ]
        state["findings"] = [
            {"severity": "critical"}, {"severity": "high"}, {"severity": "medium"},
        ]
        state["active_sessions"] = {"1": {"target": "172.28.0.10"}}
        state["current_phase"] = "reporting"
        success = calculate_engagement_success(state)
        assert success["overall"] > 30

    def test_comprehensive_report_generation(self) -> None:
        from src.evaluation import build_engagement_report

        state = self._build_state()
        state["discovered_targets"] = [
            {"ip": "172.28.0.10"}, {"ip": "172.28.0.12"},
        ]
        state["findings"] = [
            {"severity": "critical"}, {"severity": "high"},
        ]
        state["strategy_history"] = [{"decision": "transition"}] * 6
        state["critic_feedback"] = [{"severity": "warning"}]
        state["step_count"] = 20
        state["risk_score"] = 40.0
        state["current_phase"] = "reporting"
        state["messages"] = []

        report = build_engagement_report(state)
        assert report.overall_score > 0
        md = report.to_markdown()
        assert "Red Team Engagement Report" in md


# ══════════════════════════════════════════════════════════════════════════════
# BATCH RUNNER — run all scenarios and produce JSON report
# ══════════════════════════════════════════════════════════════════════════════

ALL_SCENARIOS: list[dict[str, Any]] = [
    {
        "id": 1, "name": "Pure Recon — DVWA (Safe Mode)",
        "mode": "safe", "targets": ["172.28.0.10"],
        "discovered": [{"ip": "172.28.0.10", "open_ports": [80, 443], "services": ["http"]}],
        "findings": [{"target": "172.28.0.10", "severity": "medium", "vulnerability": "XSS"}],
        "sessions": {},
    },
    {
        "id": 2, "name": "Full Scan — DVWA (Dynamic)",
        "mode": "dynamic", "targets": ["172.28.0.10"],
        "discovered": [{"ip": "172.28.0.10", "open_ports": [80, 443, 8080], "services": ["http"]}],
        "findings": [
            {"target": "172.28.0.10", "severity": "critical", "vulnerability": "SQLi"},
            {"target": "172.28.0.10", "severity": "high", "vulnerability": "XSS"},
        ],
        "sessions": {"1": {"target": "172.28.0.10"}},
    },
    {
        "id": 3, "name": "Multi-Target — DVWA + Struts",
        "mode": "dynamic", "targets": ["172.28.0.10", "172.28.0.12"],
        "discovered": [
            {"ip": "172.28.0.10", "open_ports": [80], "services": ["apache"]},
            {"ip": "172.28.0.12", "open_ports": [8080], "services": ["apache"]},
        ],
        "findings": [
            {"target": "172.28.0.10", "severity": "critical", "vulnerability": "SQLi"},
            {"target": "172.28.0.12", "severity": "critical", "vulnerability": "RCE"},
        ],
        "sessions": {"1": {"target": "172.28.0.10"}},
    },
    {
        "id": 4, "name": "High-Stealth — Mixed",
        "mode": "dynamic", "targets": ["172.28.0.10", "172.28.0.13"],
        "discovered": [
            {"ip": "172.28.0.10", "open_ports": [80], "services": []},
            {"ip": "172.28.0.13", "open_ports": [22], "services": ["ssh"]},
        ],
        "findings": [
            {"target": "172.28.0.10", "severity": "high", "vulnerability": "OpenRedirect"},
            {"target": "172.28.0.13", "severity": "high", "vulnerability": "WeakSSH"},
        ],
        "sessions": {},
        "stealth": True,
    },
    {
        "id": 5, "name": "Failed Exploit Recovery",
        "mode": "dynamic", "targets": ["172.28.0.12"],
        "discovered": [{"ip": "172.28.0.12", "open_ports": [8080], "services": []}],
        "findings": [{"target": "172.28.0.12", "severity": "critical", "vulnerability": "RCE"}],
        "sessions": {},
        "errors": [
            {"tool_name": "msf_run_exploit", "error_message": "timeout"},
            {"tool_name": "msf_search_exploits", "error_message": "RPC error"},
        ],
        "consec_failures": 3, "phase_failures": {"exploitation": 3},
    },
    {
        "id": 6, "name": "Time-Limited (10 steps)",
        "mode": "dynamic", "targets": ["172.28.0.10"],
        "max_steps": 10,
        "discovered": [{"ip": "172.28.0.10", "open_ports": [80], "services": []}],
        "findings": [{"target": "172.28.0.10", "severity": "medium", "vulnerability": "InfoLeak"}],
        "sessions": {},
    },
    {
        "id": 7, "name": "High-Risk Critic Intervention",
        "mode": "dynamic", "targets": ["172.28.0.10"],
        "discovered": [],
        "findings": [
            {"target": "172.28.0.10", "severity": "critical", "vulnerability": f"Vuln{i}"}
            for i in range(5)
        ],
        "sessions": {},
    },
    {
        "id": 8, "name": "Complete Aggressive Engagement",
        "mode": "aggressive", "targets": ["172.28.0.10", "172.28.0.12", "172.28.0.13"],
        "discovered": [
            {"ip": "172.28.0.10", "open_ports": [80, 443], "services": []},
            {"ip": "172.28.0.12", "open_ports": [8080], "services": []},
            {"ip": "172.28.0.13", "open_ports": [22], "services": []},
        ],
        "findings": [
            {"target": "172.28.0.10", "severity": "critical", "vulnerability": "SQLi"},
            {"target": "172.28.0.12", "severity": "critical", "vulnerability": "RCE"},
            {"target": "172.28.0.13", "severity": "high", "vulnerability": "WeakSSH"},
        ],
        "sessions": {"1": {"target": "172.28.0.10"}, "2": {"target": "172.28.0.12"}},
    },
]


def run_all_scenarios() -> list[ScenarioResult]:
    """Run all scenarios and return structured results."""
    results: list[ScenarioResult] = []

    for scenario in ALL_SCENARIOS:
        preset = MODE_PRESETS.get(scenario["mode"], MODE_PRESETS["dynamic"])
        state = initial_state(
            targets=scenario["targets"],
            max_steps=scenario.get("max_steps", preset["max_steps"]),
            aggression_level=preset["aggression_level"],
            stealth_mode=scenario.get("stealth", preset["stealth_mode"]),
        )
        state["discovered_targets"] = scenario.get("discovered", [])
        state["findings"] = scenario.get("findings", [])
        state["active_sessions"] = scenario.get("sessions", {})
        state["error_log"] = scenario.get("errors", [])
        state["consecutive_failures"] = scenario.get("consec_failures", 0)
        state["phase_failures"] = scenario.get("phase_failures", {})

        state = _run_planner_loop(state)

        result = ScenarioResult(
            scenario_id=scenario["id"],
            scenario_name=scenario["name"],
            mode=scenario["mode"],
            targets=scenario["targets"],
            execution_trace=state.get("_trace", []),
        )
        result.compute_scores(state)
        results.append(result)

    return results


def save_results_json(results: list[ScenarioResult], path: Path | None = None) -> Path:
    """Save results to JSON."""
    if path is None:
        report_dir = Path("logs/test_reports")
        report_dir.mkdir(parents=True, exist_ok=True)
        ts = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        path = report_dir / f"test_suite_{ts}.json"

    data = {
        "timestamp": dt.datetime.now(dt.UTC).isoformat(),
        "scenario_count": len(results),
        "results": [r.to_dict() for r in results],
        "summary": {
            "avg_success": round(sum(r.success_rate for r in results) / max(len(results), 1), 1),
            "avg_safety": round(sum(r.safety_compliance for r in results) / max(len(results), 1), 1),
            "avg_efficiency": round(sum(r.efficiency for r in results) / max(len(results), 1), 1),
            "avg_risk_mgmt": round(sum(r.risk_management for r in results) / max(len(results), 1), 1),
            "avg_smoothness": round(sum(r.phase_smoothness for r in results) / max(len(results), 1), 1),
            "avg_overall": round(sum(r.overall for r in results) / max(len(results), 1), 1),
        },
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return path


# ── Standalone runner ────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("🔴 Running Dynamic Test Suite — 8 Scenarios\n")
    results = run_all_scenarios()
    path = save_results_json(results)
    print(f"\nResults saved to: {path}\n")
    for r in results:
        grade = "✅" if r.overall >= 60 else "⚠️" if r.overall >= 40 else "❌"
        print(f"  {grade} [{r.scenario_id}] {r.scenario_name}: {r.overall}/100")
    print()
    avg = sum(r.overall for r in results) / len(results)
    print(f"  📊 Average Score: {avg:.1f}/100")
