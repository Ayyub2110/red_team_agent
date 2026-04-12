"""Integration tests for the LangGraph agent graph structure."""

from __future__ import annotations

import pytest

# os.environ["ALLOWED_TARGET_SUBNET"] = "172.28.0.0/24"
# os.environ["REQUIRE_HUMAN_APPROVAL"] = "false"


@pytest.fixture(autouse=True)
def reset_settings():
    """Reset the settings singleton before each test."""
    from src import config
    config._settings = None
    yield
    config._settings = None


class TestGraphConstruction:
    """Verify the agent graph builds correctly without requiring Ollama."""

    def test_graph_compiles(self) -> None:
        """Graph should compile without errors."""
        from src.agent.graph import ALL_TOOLS

        # Verify all tools are registered
        assert len(ALL_TOOLS) == 11

        tool_names = {t.name for t in ALL_TOOLS}
        assert "nmap_scan" in tool_names
        assert "msf_run_exploit" in tool_names
        assert "ping_sweep" in tool_names
        assert "http_get" in tool_names

    def test_approval_required_tools(self) -> None:
        """Only exploit-type tools should require approval."""
        from src.agent.graph import APPROVAL_REQUIRED_TOOLS

        assert "msf_run_exploit" in APPROVAL_REQUIRED_TOOLS
        assert "nmap_scan" not in APPROVAL_REQUIRED_TOOLS

    def test_initial_state_structure(self) -> None:
        """Initial state should have all required keys."""
        from src.agent.state import initial_state

        state = initial_state()
        required_keys = [
            "messages",
            "current_phase",
            "targets",
            "findings",
            "sessions",
            "step_count",
            "plan",
            "human_feedback",
            # Strategic fields
            "risk_score",
            "discovered_targets",
            "active_sessions",
            "strategy_history",
            "aggression_level",
            "stealth_mode",
            # Error tracking fields
            "error_log",
            "phase_failures",
            "consecutive_failures",
            "total_errors",
            "kill_switch_triggered",
            "kill_switch_reason",
            "critic_feedback",
            "last_successful_phase",
        ]
        for key in required_keys:
            assert key in state, f"Missing key: {key}"

    def test_tool_classification(self) -> None:
        """Phase-specific tool lists should contain the correct tools."""
        from src.agent.graph import (
            EXPLOIT_TOOLS,
            FALLBACK_TOOLS,
            RECON_TOOLS,
            SCANNING_TOOLS,
        )

        recon_names = {t.name for t in RECON_TOOLS}
        assert "ping_sweep" in recon_names
        assert "banner_grab" in recon_names

        scan_names = {t.name for t in SCANNING_TOOLS}
        assert "nmap_scan" in scan_names
        assert "directory_bruteforce" in scan_names

        exploit_names = {t.name for t in EXPLOIT_TOOLS}
        assert "msf_run_exploit" in exploit_names
        assert "msf_search_exploits" in exploit_names

        # Fallback tools should not include Metasploit
        fallback_names = {t.name for t in FALLBACK_TOOLS}
        assert "nmap_scan" in fallback_names
        assert "msf_run_exploit" not in fallback_names

    def test_mode_presets_exist(self) -> None:
        """Verify mode presets are properly defined."""
        from src.agent.graph import MODE_PRESETS

        assert "dynamic" in MODE_PRESETS
        assert "safe" in MODE_PRESETS
        assert "aggressive" in MODE_PRESETS

        assert MODE_PRESETS["safe"]["aggression_level"] == "low"
        assert MODE_PRESETS["safe"]["stealth_mode"] is True
        assert MODE_PRESETS["aggressive"]["aggression_level"] == "high"
        assert MODE_PRESETS["dynamic"]["aggression_level"] == "medium"

    def test_specialist_tool_sets(self) -> None:
        """Verify specialist tool lists are populated."""
        from src.agent.graph import NETWORK_SPECIALIST_TOOLS, WEB_SPECIALIST_TOOLS

        web_names = {t.name for t in WEB_SPECIALIST_TOOLS}
        assert "http_get" in web_names
        assert "directory_bruteforce" in web_names

        network_names = {t.name for t in NETWORK_SPECIALIST_TOOLS}
        assert "nmap_scan" in network_names
        assert "tcp_syn_scan" in network_names

    def test_adaptive_strategy_node_returns_plan(self) -> None:
        """Adaptive strategy node should produce a plan string."""
        from src.agent.graph import adaptive_strategy_node
        from src.agent.state import initial_state

        state = initial_state(targets=["172.28.0.10"])
        state["current_phase"] = "scanning"
        state["discovered_targets"] = [
            {"ip": "172.28.0.10", "open_ports": [80], "services": ["http"]},
        ]

        result = adaptive_strategy_node(state)
        assert "plan" in result
        assert "Strategy" in result["plan"]
        assert "scanning" in result["plan"]


class TestPhaseTransitions:
    """Verify phase transition logic."""

    def test_phases_ordered(self) -> None:
        from src.agent.state import PHASES

        assert PHASES == [
            "reconnaissance",
            "scanning",
            "exploitation",
            "post_exploitation",
            "reporting",
        ]

    def test_extended_phases_ordered(self) -> None:
        from src.agent.state import EXTENDED_PHASES

        assert EXTENDED_PHASES == [
            "reconnaissance",
            "scanning",
            "exploitation",
            "post_exploitation",
            "triage",
            "remediation",
            "reporting",
        ]

    def test_strategic_planner_recon_to_scanning(self) -> None:
        """Planner should transition from recon to scanning when targets found."""
        from src.agent.graph import strategic_planner_node
        from src.agent.state import initial_state

        state = initial_state(targets=["172.28.0.0/24"])
        state["discovered_targets"] = [
            {"ip": "172.28.0.10", "hostname": "dvwa"},
        ]

        result = strategic_planner_node(state)
        assert result["current_phase"] == "scanning"

    def test_strategic_planner_stays_in_recon(self) -> None:
        """Planner should stay in recon when no targets discovered."""
        from src.agent.graph import strategic_planner_node
        from src.agent.state import initial_state

        state = initial_state(targets=["172.28.0.0/24"])
        result = strategic_planner_node(state)
        assert result["current_phase"] == "reconnaissance"

    def test_strategic_planner_scanning_to_exploitation(self) -> None:
        """Planner should escalate to exploitation when critical finding exists."""
        from src.agent.graph import strategic_planner_node
        from src.agent.state import initial_state

        state = initial_state(targets=["172.28.0.10"])
        state["current_phase"] = "scanning"
        state["findings"] = [
            {"severity": "critical", "target": "172.28.0.10", "vulnerability": "RCE"},
        ]

        result = strategic_planner_node(state)
        assert result["current_phase"] == "exploitation"

    def test_strategic_planner_low_aggression_skips_exploit(self) -> None:
        """In low aggression mode, planner skips exploitation entirely."""
        from src.agent.graph import strategic_planner_node
        from src.agent.state import initial_state

        state = initial_state(
            targets=["172.28.0.10"], aggression_level="low"
        )
        state["current_phase"] = "scanning"
        state["findings"] = [
            {"severity": "critical", "target": "172.28.0.10", "vulnerability": "RCE"},
        ]

        result = strategic_planner_node(state)
        assert result["current_phase"] == "triage"

    def test_strategic_planner_forces_report_at_step_limit(self) -> None:
        """Planner should force reporting when step limit is hit."""
        from src.agent.graph import strategic_planner_node
        from src.agent.state import initial_state

        state = initial_state(max_steps=10)
        state["step_count"] = 10

        result = strategic_planner_node(state)
        assert result["current_phase"] == "reporting"


class TestKillSwitch:
    """Verify kill-switch triggers in the strategic planner."""

    def test_kill_switch_on_error_threshold(self) -> None:
        """Kill switch fires when total_errors >= threshold."""
        from src.agent.graph import strategic_planner_node
        from src.agent.state import KILL_SWITCH_ERROR_THRESHOLD, initial_state

        state = initial_state(targets=["172.28.0.10"])
        state["total_errors"] = KILL_SWITCH_ERROR_THRESHOLD

        result = strategic_planner_node(state)
        assert result["current_phase"] == "reporting"
        assert result["kill_switch_triggered"] is True
        assert "Total errors" in result["kill_switch_reason"]

    def test_kill_switch_on_risk_threshold_medium(self) -> None:
        """Kill switch fires when risk > 80 in medium aggression."""
        from src.agent.graph import strategic_planner_node
        from src.agent.state import Finding, initial_state

        state = initial_state(targets=["172.28.0.10"], aggression_level="medium")
        # 4 critical findings = risk score 100, > 80 threshold
        state["findings"] = [
            Finding(target="172.28.0.10", vulnerability=f"vuln{i}", severity="critical").to_dict()
            for i in range(4)
        ]

        result = strategic_planner_node(state)
        assert result["kill_switch_triggered"] is True
        assert result["current_phase"] == "reporting"

    def test_kill_switch_spared_in_aggressive_mode(self) -> None:
        """High aggression mode does NOT trigger risk-based kill switch."""
        from src.agent.graph import strategic_planner_node
        from src.agent.state import Finding, initial_state

        state = initial_state(targets=["172.28.0.10"], aggression_level="high")
        state["current_phase"] = "scanning"
        state["findings"] = [
            Finding(target="172.28.0.10", vulnerability=f"vuln{i}", severity="critical").to_dict()
            for i in range(4)
        ]

        result = strategic_planner_node(state)
        # Should NOT trigger kill switch — aggressive mode tolerates high risk
        assert result.get("kill_switch_triggered") is not True

    def test_kill_switch_on_consecutive_failures(self) -> None:
        """Kill switch fires on excessive consecutive failures."""
        from src.agent.graph import strategic_planner_node
        from src.agent.state import MAX_CONSECUTIVE_FAILURES, initial_state

        state = initial_state(targets=["172.28.0.10"])
        state["consecutive_failures"] = MAX_CONSECUTIVE_FAILURES * 2

        result = strategic_planner_node(state)
        assert result["kill_switch_triggered"] is True


class TestCriticNode:
    """Verify the critic node's self-correction logic."""

    def test_stuck_detection(self) -> None:
        """Critic detects when the agent is stuck in the same phase."""
        from src.agent.graph import critic_node
        from src.agent.state import initial_state

        state = initial_state()
        state["current_phase"] = "scanning"
        state["strategy_history"] = [
            {"decision": "stay", "phase": "scanning"},
            {"decision": "stay", "phase": "scanning"},
            {"decision": "stay", "phase": "scanning"},
        ]

        result = critic_node(state)
        feedback = result["critic_feedback"]
        assert len(feedback) >= 1
        assert any("Stuck" in f.get("issue", "") for f in feedback)

    def test_phase_failure_detection(self) -> None:
        """Critic detects when a phase has too many failures."""
        from src.agent.graph import critic_node
        from src.agent.state import MAX_CONSECUTIVE_FAILURES, initial_state

        state = initial_state()
        state["current_phase"] = "exploitation"
        state["phase_failures"] = {"exploitation": MAX_CONSECUTIVE_FAILURES}

        result = critic_node(state)
        feedback = result["critic_feedback"]
        assert any("failed" in f.get("issue", "").lower() for f in feedback)

    def test_msf_fallback_suggestion(self) -> None:
        """Critic suggests fallback when Metasploit fails repeatedly."""
        from src.agent.graph import critic_node
        from src.agent.state import initial_state

        state = initial_state()
        state["error_log"] = [
            {"tool_name": "msf_run_exploit", "error_message": "Connection refused"},
            {"tool_name": "msf_search_exploits", "error_message": "RPC timeout"},
        ]

        result = critic_node(state)
        feedback = result["critic_feedback"]
        assert any("Metasploit" in f.get("issue", "") for f in feedback)
        assert any("falling back" in f.get("suggestion", "").lower() for f in feedback)

    def test_no_findings_stagnation(self) -> None:
        """Critic flags stagnation when no findings after many steps."""
        from src.agent.graph import critic_node
        from src.agent.state import initial_state

        state = initial_state()
        state["step_count"] = 15
        state["findings"] = []

        result = critic_node(state)
        feedback = result["critic_feedback"]
        assert any("No findings" in f.get("issue", "") for f in feedback)

    def test_auto_skip_on_critical_feedback(self) -> None:
        """Critic auto-skips a hard-failing phase when critical."""
        from src.agent.graph import critic_node
        from src.agent.state import MAX_CONSECUTIVE_FAILURES, initial_state

        state = initial_state()
        state["current_phase"] = "exploitation"
        state["phase_failures"] = {"exploitation": MAX_CONSECUTIVE_FAILURES}
        state["consecutive_failures"] = MAX_CONSECUTIVE_FAILURES

        result = critic_node(state)
        # Should force a phase advance
        assert result.get("current_phase") == "post_exploitation"
        assert result.get("consecutive_failures") == 0  # Reset


class TestRecoveryNode:
    """Verify the recovery node's graceful degradation logic."""

    def test_recovery_produces_plan(self) -> None:
        """Recovery node should produce a recovery plan."""
        from src.agent.graph import recovery_node
        from src.agent.state import initial_state

        state = initial_state()
        state["error_log"] = [
            {"tool_name": "msf_run_exploit", "error_message": "timeout"},
        ]

        result = recovery_node(state)
        assert "Recovery" in result["plan"]
        assert "fallback_to_manual" in result["plan"]

    def test_recovery_for_network_error(self) -> None:
        from src.agent.graph import recovery_node
        from src.agent.state import initial_state

        state = initial_state()
        state["error_log"] = [
            {"tool_name": "ping_sweep", "error_message": "Network unreachable"},
        ]

        result = recovery_node(state)
        assert "retry_with_delay" in result["plan"]


class TestEvaluationReport:
    """Verify the engagement report builder."""

    def test_report_from_empty_state(self) -> None:
        """Report should handle an empty state gracefully."""
        from src.evaluation import build_engagement_report

        state = {
            "findings": [],
            "strategy_history": [],
            "critic_feedback": [],
            "error_log": [],
            "current_phase": "reconnaissance",
            "step_count": 0,
            "risk_score": 0.0,
            "targets": [],
            "discovered_targets": [],
            "active_sessions": {},
            "total_errors": 0,
            "consecutive_failures": 0,
            "kill_switch_triggered": False,
            "kill_switch_reason": "",
            "aggression_level": "medium",
            "stealth_mode": False,
            "messages": [],
        }

        report = build_engagement_report(state)
        assert report.overall_score >= 0
        assert report.safety_score > 0  # Base safety should be high

    def test_report_with_findings(self) -> None:
        from src.evaluation import build_engagement_report

        state = {
            "findings": [
                {"severity": "critical"},
                {"severity": "high"},
                {"severity": "medium"},
            ],
            "strategy_history": [{"decision": "transition"}] * 5,
            "critic_feedback": [{"severity": "warning"}],
            "error_log": [],
            "current_phase": "triage",
            "step_count": 20,
            "risk_score": 48.0,
            "targets": ["172.28.0.10"],
            "discovered_targets": [{"ip": "172.28.0.10"}],
            "active_sessions": {"1": {"target": "172.28.0.10"}},
            "total_errors": 0,
            "consecutive_failures": 0,
            "kill_switch_triggered": False,
            "kill_switch_reason": "",
            "aggression_level": "medium",
            "stealth_mode": False,
            "messages": [],
        }

        report = build_engagement_report(state)
        assert report.total_findings == 3
        assert report.critical_findings == 1
        assert report.success_score > 0
        assert report.overall_score > 0

    def test_report_markdown_generation(self) -> None:
        from src.evaluation import build_engagement_report

        state = {
            "findings": [{"severity": "high"}],
            "strategy_history": [{"decision": "stay"}],
            "critic_feedback": [],
            "error_log": [],
            "current_phase": "reporting",
            "step_count": 10,
            "risk_score": 15.0,
            "targets": ["172.28.0.10"],
            "discovered_targets": [{"ip": "172.28.0.10"}],
            "active_sessions": {},
            "total_errors": 1,
            "consecutive_failures": 0,
            "kill_switch_triggered": False,
            "kill_switch_reason": "",
            "aggression_level": "medium",
            "stealth_mode": False,
            "messages": [],
        }

        report = build_engagement_report(state)
        md = report.to_markdown()
        assert "Red Team Engagement Report" in md
        assert "Success" in md
        assert "Safety" in md
        assert "Efficiency" in md
        assert "Creativity" in md

    def test_score_grading(self) -> None:
        from src.evaluation import _score_to_grade

        assert _score_to_grade(95) == "A+"
        assert _score_to_grade(85) == "A"
        assert _score_to_grade(75) == "B"
        assert _score_to_grade(65) == "C"
        assert _score_to_grade(55) == "D"
        assert _score_to_grade(30) == "F"
