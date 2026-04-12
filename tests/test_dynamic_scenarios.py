"""Dynamic test scenarios for the phase-aware red team agent.

These tests validate the strategic planner's deterministic routing logic,
the adaptive strategy engine, specialist sub-agent routing, and self-correction
across 10 realistic engagement scenarios — without requiring Ollama or
a live cyber range.
"""

from __future__ import annotations

import pytest

from src.agent.graph import (
    adaptive_strategy_node,
    critic_node,
    strategic_planner_node,
)
from src.agent.state import (
    DiscoveredTarget,
    Finding,
    StrategyEntry,
    calculate_engagement_success,
    calculate_risk_score,
    initial_state,
)
from src.agent.strategy import (
    TARGET_TYPE_SSH,
    TARGET_TYPE_UNKNOWN,
    TARGET_TYPE_WEB,
    TARGET_TYPE_WINDOWS,
    StrategyRecommendation,
    classify_all_targets,
    classify_target,
    compute_strategy,
    determine_specialist,
)


@pytest.fixture(autouse=True)
def reset_settings():
    """Reset the settings singleton before each test."""
    from src import config
    config._settings = None
    yield
    config._settings = None


# ═════════════════════════════════════════════════════════════════════════════
# Scenario 1: Recon-only on one target (low aggression)
# ═════════════════════════════════════════════════════════════════════════════
class TestScenarioReconOnly:
    """Low-aggression engagement: recon → scanning → triage (skip exploit)."""

    def test_recon_stays_until_targets_found(self) -> None:
        state = initial_state(targets=["172.28.0.12"], aggression_level="low")
        result = strategic_planner_node(state)
        assert result["current_phase"] == "reconnaissance"
        assert result["risk_score"] == 0.0

    def test_recon_transitions_to_scanning(self) -> None:
        state = initial_state(targets=["172.28.0.12"], aggression_level="low")
        state["discovered_targets"] = [
            DiscoveredTarget(ip="172.28.0.12", open_ports=[80, 8080]).to_dict(),
        ]
        result = strategic_planner_node(state)
        assert result["current_phase"] == "scanning"

    def test_scanning_skips_to_triage_on_low_aggression(self) -> None:
        state = initial_state(targets=["172.28.0.12"], aggression_level="low")
        state["current_phase"] = "scanning"
        state["findings"] = [
            Finding(
                target="172.28.0.12",
                vulnerability="Apache Struts2 RCE",
                severity="critical",
                port=8080,
            ).to_dict(),
        ]
        result = strategic_planner_node(state)
        assert result["current_phase"] == "triage"
        assert result["risk_score"] == 25.0

    def test_triage_moves_to_remediation(self) -> None:
        state = initial_state(aggression_level="low")
        state["current_phase"] = "triage"
        result = strategic_planner_node(state)
        assert result["current_phase"] == "remediation"

    def test_remediation_moves_to_reporting(self) -> None:
        state = initial_state(aggression_level="low")
        state["current_phase"] = "remediation"
        result = strategic_planner_node(state)
        assert result["current_phase"] == "reporting"


# ═════════════════════════════════════════════════════════════════════════════
# Scenario 2: Full assessment with human approval gates
# ═════════════════════════════════════════════════════════════════════════════
class TestScenarioFullAssessment:
    """Full kill-chain: recon → scan → exploit → post → triage → remediation → reporting."""

    def test_full_lifecycle(self) -> None:
        state = initial_state(
            targets=["172.28.0.10", "172.28.0.12"],
            aggression_level="medium",
        )

        # Step 1: recon — no targets → stay
        r1 = strategic_planner_node(state)
        assert r1["current_phase"] == "reconnaissance"

        # Step 2: recon → scanning
        state["current_phase"] = "reconnaissance"
        state["discovered_targets"] = [
            DiscoveredTarget(ip="172.28.0.10", open_ports=[80]).to_dict(),
            DiscoveredTarget(ip="172.28.0.12", open_ports=[8080]).to_dict(),
        ]
        r2 = strategic_planner_node(state)
        assert r2["current_phase"] == "scanning"

        # Step 3: scanning → exploitation
        state["current_phase"] = "scanning"
        state["findings"] = [
            Finding(target="172.28.0.10", vulnerability="SQL Injection", severity="critical").to_dict(),
        ]
        r3 = strategic_planner_node(state)
        assert r3["current_phase"] == "exploitation"

        # Step 4: exploitation → post
        state["current_phase"] = "exploitation"
        state["active_sessions"] = {"1": {"target": "172.28.0.10", "module": "exploit/http/sqli"}}
        r4 = strategic_planner_node(state)
        assert r4["current_phase"] == "post_exploitation"

        # Steps 5-7: post → triage → remediation → reporting
        for from_phase, to_phase in [
            ("post_exploitation", "triage"),
            ("triage", "remediation"),
            ("remediation", "reporting"),
        ]:
            state["current_phase"] = from_phase
            result = strategic_planner_node(state)
            assert result["current_phase"] == to_phase

    def test_strategy_history_accumulates(self) -> None:
        state = initial_state(targets=["172.28.0.10"])
        state["discovered_targets"] = [DiscoveredTarget(ip="172.28.0.10").to_dict()]
        r = strategic_planner_node(state)
        assert len(r["strategy_history"]) == 1
        assert r["strategy_history"][0]["decision"] == "transition → scanning"


# ═════════════════════════════════════════════════════════════════════════════
# Scenario 3: Multi-target coordinated attack (low aggression)
# ═════════════════════════════════════════════════════════════════════════════
class TestScenarioMultiTargetLowAggression:
    """4 targets, low aggression — should never reach exploitation."""

    def test_multi_target_stays_defensive(self) -> None:
        state = initial_state(
            targets=["172.28.0.10", "172.28.0.11", "172.28.0.12", "172.28.0.13"],
            aggression_level="low",
        )
        state["current_phase"] = "scanning"
        state["discovered_targets"] = [
            DiscoveredTarget(ip=f"172.28.0.{x}", open_ports=[80]).to_dict()
            for x in [10, 11, 12, 13]
        ]
        state["findings"] = [
            Finding(target="172.28.0.10", vulnerability="SQLi", severity="critical").to_dict(),
            Finding(target="172.28.0.11", vulnerability="XSS", severity="high").to_dict(),
            Finding(target="172.28.0.12", vulnerability="RCE", severity="critical").to_dict(),
            Finding(target="172.28.0.13", vulnerability="Weak SSH", severity="high").to_dict(),
        ]
        result = strategic_planner_node(state)
        assert result["current_phase"] == "triage"
        assert result["risk_score"] == 80.0

    def test_risk_score_reflects_all_targets(self) -> None:
        findings = [{"severity": "critical"}, {"severity": "critical"}, {"severity": "high"}, {"severity": "high"}]
        assert calculate_risk_score(findings) == 80.0

    def test_engagement_success_with_no_exploitation(self) -> None:
        state = initial_state(
            targets=["172.28.0.10", "172.28.0.11", "172.28.0.12", "172.28.0.13"],
            aggression_level="low",
        )
        state["discovered_targets"] = [{"ip": f"172.28.0.{x}"} for x in [10, 11, 12, 13]]
        state["findings"] = [{"severity": "critical"}, {"severity": "high"}]
        state["current_phase"] = "triage"
        success = calculate_engagement_success(state)
        assert success["overall"] > 0
        assert success["exploitation_rate"] == 0.0
        assert success["discovery_rate"] == 100.0


# ═════════════════════════════════════════════════════════════════════════════
# Scenario 4: Recovery from failed exploit
# ═════════════════════════════════════════════════════════════════════════════
class TestScenarioExploitRecovery:
    """Failed exploits with risk-based progression."""

    def test_no_sessions_stays_in_exploitation(self) -> None:
        state = initial_state(targets=["172.28.0.12"])
        state["current_phase"] = "exploitation"
        state["findings"] = [
            Finding(target="172.28.0.12", vulnerability="RCE", severity="medium").to_dict(),
        ]
        result = strategic_planner_node(state)
        assert result["current_phase"] == "exploitation"

    def test_high_risk_forces_progression(self) -> None:
        state = initial_state(targets=["172.28.0.12"])
        state["current_phase"] = "exploitation"
        state["findings"] = [
            Finding(target="172.28.0.12", vulnerability=f"v{i}", severity="critical").to_dict()
            for i in range(3)
        ]
        result = strategic_planner_node(state)
        assert result["current_phase"] == "post_exploitation"
        assert result["risk_score"] == 75.0

    def test_step_limit_overrides_everything(self) -> None:
        state = initial_state(targets=["172.28.0.12"], max_steps=5)
        state["current_phase"] = "exploitation"
        state["step_count"] = 5
        result = strategic_planner_node(state)
        assert result["current_phase"] == "reporting"


# ═════════════════════════════════════════════════════════════════════════════
# Scenario 5: High-stealth mode
# ═════════════════════════════════════════════════════════════════════════════
class TestScenarioHighStealth:
    """Stealth mode propagation and prompt injection."""

    def test_stealth_state_propagated(self) -> None:
        state = initial_state(targets=["172.28.0.10"], stealth_mode=True)
        assert state["stealth_mode"] is True

    def test_stealth_in_prompt(self) -> None:
        from src.agent.prompts import build_system_prompt
        state = initial_state(targets=["172.28.0.10"], stealth_mode=True)
        prompt = build_system_prompt(dict(state))
        assert "STEALTH MODE" in prompt
        assert "SYN scans" in prompt

    def test_stealth_does_not_affect_phase_logic(self) -> None:
        state = initial_state(targets=["172.28.0.10"], stealth_mode=True)
        state["discovered_targets"] = [DiscoveredTarget(ip="172.28.0.10", open_ports=[80]).to_dict()]
        result = strategic_planner_node(state)
        assert result["current_phase"] == "scanning"

    def test_aggression_level_combo(self) -> None:
        from src.agent.prompts import build_system_prompt
        state = initial_state(targets=["172.28.0.10"], stealth_mode=True, aggression_level="high")
        prompt = build_system_prompt(dict(state))
        assert "STEALTH MODE" in prompt
        assert "HIGH AGGRESSION" in prompt

    def test_engagement_success_with_stealth(self) -> None:
        state = initial_state(targets=["172.28.0.10"], stealth_mode=True)
        state["discovered_targets"] = [{"ip": "172.28.0.10"}]
        state["findings"] = [{"severity": "high"}]
        success = calculate_engagement_success(state)
        assert success["overall"] > 0


# ═════════════════════════════════════════════════════════════════════════════
# Scenario 6: Defensive target with IDS simulation
# ═════════════════════════════════════════════════════════════════════════════
class TestScenarioDefensiveTargetWithIDS:
    """Simulate an engagement against a target with IDS-like behaviour.

    When stealth mode is on, the strategy engine should recommend SYN scans
    and the critic should flag repeated failures as potential IDS blocking.
    """

    def test_stealth_strategy_recommends_syn_scans(self) -> None:
        """Strategy engine should prefer SYN scans in stealth mode."""
        state = initial_state(targets=["172.28.0.10"], stealth_mode=True)
        state["current_phase"] = "scanning"
        state["discovered_targets"] = [
            DiscoveredTarget(ip="172.28.0.10", open_ports=[80, 443]).to_dict(),
        ]

        rec = compute_strategy(dict(state))
        assert "tcp_syn_scan" in rec.recommended_tools
        assert rec.approach == "stealth_scan"

    def test_ids_blocking_triggers_critic_warnings(self) -> None:
        """Consecutive scan failures should be flagged by the critic."""
        state = initial_state(targets=["172.28.0.10"], stealth_mode=True)
        state["current_phase"] = "scanning"
        state["consecutive_failures"] = 3
        state["phase_failures"] = {"scanning": 3}
        state["error_log"] = [
            {"tool_name": "nmap_scan", "error_message": "Connection reset"},
            {"tool_name": "tcp_syn_scan", "error_message": "Host unreachable"},
        ]

        result = critic_node(state)
        feedback = result["critic_feedback"]
        assert len(feedback) >= 2  # Phase failure + consecutive failure warnings

    def test_stealth_fallback_after_repeated_blocks(self) -> None:
        """With 3+ failures in scanning, critic should force phase skip."""
        state = initial_state(targets=["172.28.0.10"], stealth_mode=True)
        state["current_phase"] = "scanning"
        state["phase_failures"] = {"scanning": 3}
        state["consecutive_failures"] = 3
        state["error_log"] = [
            {"tool_name": "nmap_scan", "error_message": "filtered"},
        ]

        result = critic_node(state)
        # Critical feedback should trigger auto-skip to exploitation
        assert result.get("current_phase") == "exploitation"
        assert result.get("consecutive_failures") == 0

    def test_low_aggression_ids_goes_to_triage(self) -> None:
        """Low aggression + IDS failures → skip to triage, not exploitation."""
        state = initial_state(targets=["172.28.0.10"], stealth_mode=True, aggression_level="low")
        state["current_phase"] = "scanning"
        state["findings"] = [
            Finding(target="172.28.0.10", vulnerability="Suspected web vuln", severity="medium").to_dict(),
        ]
        result = strategic_planner_node(state)
        # Low aggression: findings present → triage
        assert result["current_phase"] == "triage"


# ═════════════════════════════════════════════════════════════════════════════
# Scenario 7: Time-limited engagement
# ═════════════════════════════════════════════════════════════════════════════
class TestScenarioTimeLimited:
    """Simulate a tight time budget (max_steps=8) forcing early termination."""

    def test_short_engagement_forces_report(self) -> None:
        """With max_steps=8, agent should wrap up quickly."""
        state = initial_state(targets=["172.28.0.10"], max_steps=8)
        state["step_count"] = 8
        state["current_phase"] = "scanning"

        result = strategic_planner_node(state)
        assert result["current_phase"] == "reporting"

    def test_partial_findings_preserved(self) -> None:
        """Findings should be preserved even with early termination."""
        state = initial_state(targets=["172.28.0.10"], max_steps=5)
        state["step_count"] = 5
        state["findings"] = [
            Finding(target="172.28.0.10", vulnerability="Open port 80", severity="info").to_dict(),
        ]
        result = strategic_planner_node(state)
        assert result["current_phase"] == "reporting"
        # risk_score should still reflect the finding
        assert result["risk_score"] == 1.0  # info = 1

    def test_time_limited_success_score(self) -> None:
        """Even partial engagements should get a meaningful success score."""
        state = initial_state(targets=["172.28.0.10"], max_steps=5)
        state["discovered_targets"] = [{"ip": "172.28.0.10"}]
        state["findings"] = [{"severity": "medium"}]
        state["current_phase"] = "scanning"
        state["step_count"] = 5

        success = calculate_engagement_success(state)
        assert success["overall"] > 0
        assert success["discovery_rate"] == 100.0

    def test_strategy_adapts_to_tight_budget(self) -> None:
        """Strategy engine should still work with a tiny step budget."""
        state = initial_state(targets=["172.28.0.10"], max_steps=3)
        state["current_phase"] = "reconnaissance"
        rec = compute_strategy(dict(state))
        assert rec.phase == "reconnaissance"
        assert len(rec.recommended_tools) > 0


# ═════════════════════════════════════════════════════════════════════════════
# Scenario 8: High-value target with heavy monitoring
# ═════════════════════════════════════════════════════════════════════════════
class TestScenarioHighValueTarget:
    """Simulate targeting a high-value asset (web server with many vulns).

    The strategy engine should prioritise this target and route to
    the web specialist when appropriate.
    """

    def test_web_target_classified_correctly(self) -> None:
        """Target with ports 80/443/8080 should be classified as web."""
        target = {"ip": "172.28.0.10", "open_ports": [80, 443, 8080], "services": ["http", "https"]}
        assert classify_target(target) == TARGET_TYPE_WEB

    def test_ssh_target_classified_correctly(self) -> None:
        target = {"ip": "172.28.0.13", "open_ports": [22], "services": ["OpenSSH"]}
        assert classify_target(target) == TARGET_TYPE_SSH

    def test_windows_target_classified_correctly(self) -> None:
        target = {"ip": "172.28.0.14", "open_ports": [445, 135, 3389], "services": ["microsoft-ds"]}
        assert classify_target(target) == TARGET_TYPE_WINDOWS

    def test_unknown_target_fallback(self) -> None:
        target = {"ip": "172.28.0.99", "open_ports": [], "services": []}
        assert classify_target(target) == TARGET_TYPE_UNKNOWN

    def test_web_specialist_selected_for_web_targets(self) -> None:
        profiles = classify_all_targets(
            discovered_targets=[
                {"ip": "172.28.0.10", "open_ports": [80, 443], "services": ["http"]},
                {"ip": "172.28.0.11", "open_ports": [3000], "services": ["http"]},
            ],
            findings=[],
            sessions={},
        )
        specialist = determine_specialist(profiles)
        assert specialist == "web_specialist"

    def test_network_specialist_for_ssh_windows_mix(self) -> None:
        profiles = classify_all_targets(
            discovered_targets=[
                {"ip": "172.28.0.13", "open_ports": [22], "services": ["ssh"]},
                {"ip": "172.28.0.14", "open_ports": [445, 3389], "services": ["smb"]},
            ],
            findings=[],
            sessions={},
        )
        specialist = determine_specialist(profiles)
        assert specialist == "network_specialist"

    def test_high_priority_target_ranked_first(self) -> None:
        """Targets with critical findings should be prioritised."""
        profiles = classify_all_targets(
            discovered_targets=[
                {"ip": "172.28.0.10", "open_ports": [80], "services": []},
                {"ip": "172.28.0.11", "open_ports": [80], "services": []},
            ],
            findings=[
                {"target": "172.28.0.11", "severity": "critical"},
            ],
            sessions={},
        )
        # 172.28.0.11 has critical finding → should be high priority
        high_pri = [p for p in profiles if p.priority == "high"]
        assert len(high_pri) == 1
        assert high_pri[0].ip == "172.28.0.11"

    def test_strategy_recommends_web_tools_for_web_target(self) -> None:
        state = initial_state(targets=["172.28.0.10"])
        state["current_phase"] = "scanning"
        state["discovered_targets"] = [
            {"ip": "172.28.0.10", "open_ports": [80, 443, 8080], "services": ["http"]},
        ]
        rec = compute_strategy(dict(state))
        assert "http_get" in rec.recommended_tools
        assert "directory_bruteforce" in rec.recommended_tools
        assert rec.specialist == "web_specialist"


# ═════════════════════════════════════════════════════════════════════════════
# Scenario 9: Partial compromise recovery
# ═════════════════════════════════════════════════════════════════════════════
class TestScenarioPartialCompromiseRecovery:
    """Simulate partial compromise: one target exploited, others still in scanning.

    The planner should correctly handle mixed states and the strategy engine
    should focus on unexploited targets.
    """

    def test_session_forces_post_exploit(self) -> None:
        """Even with only 1 of 3 targets exploited, having a session moves to post."""
        state = initial_state(targets=["172.28.0.10", "172.28.0.11", "172.28.0.12"])
        state["current_phase"] = "exploitation"
        state["active_sessions"] = {"1": {"target": "172.28.0.10"}}
        state["findings"] = [
            Finding(target="172.28.0.10", vulnerability="SQLi", severity="critical").to_dict(),
            Finding(target="172.28.0.11", vulnerability="XSS", severity="high").to_dict(),
        ]
        result = strategic_planner_node(state)
        assert result["current_phase"] == "post_exploitation"

    def test_strategy_focuses_unexploited_targets(self) -> None:
        """Strategy should prioritise targets that haven't been exploited."""
        state = initial_state(targets=["172.28.0.10", "172.28.0.11"])
        state["current_phase"] = "exploitation"
        state["discovered_targets"] = [
            {"ip": "172.28.0.10", "open_ports": [80], "services": []},
            {"ip": "172.28.0.11", "open_ports": [80], "services": []},
        ]
        state["active_sessions"] = {"1": {"target": "172.28.0.10"}}
        state["findings"] = [
            {"target": "172.28.0.10", "severity": "critical"},
            {"target": "172.28.0.11", "severity": "critical"},
        ]

        rec = compute_strategy(dict(state))
        # Both have critical findings, but 172.28.0.10 has a session already
        # Strategy should still list both (it doesn't exclude exploited targets)
        assert len(rec.primary_targets) == 2

    def test_mixed_target_profiles(self) -> None:
        """Profiles should correctly reflect sessions and finding counts."""
        profiles = classify_all_targets(
            discovered_targets=[
                {"ip": "172.28.0.10", "open_ports": [80], "services": []},
                {"ip": "172.28.0.11", "open_ports": [22], "services": []},
            ],
            findings=[
                {"target": "172.28.0.10", "severity": "critical"},
                {"target": "172.28.0.10", "severity": "high"},
            ],
            sessions={"1": {"target": "172.28.0.10"}},
        )
        p10 = next(p for p in profiles if p.ip == "172.28.0.10")
        p11 = next(p for p in profiles if p.ip == "172.28.0.11")

        assert p10.has_session is True
        assert p10.finding_count == 2
        assert p10.priority == "high"
        assert p11.has_session is False
        assert p11.finding_count == 0


# ═════════════════════════════════════════════════════════════════════════════
# Scenario 10: MSF failure with automatic fallback
# ═════════════════════════════════════════════════════════════════════════════
class TestScenarioMSFFallback:
    """Simulate Metasploit being completely unreachable.

    The strategy engine should automatically remove MSF tools and
    recommend manual alternatives.
    """

    def test_msf_errors_trigger_tool_removal(self) -> None:
        """After 2+ MSF errors, strategy should exclude MSF tools."""
        state = initial_state(targets=["172.28.0.10"])
        state["current_phase"] = "exploitation"
        state["discovered_targets"] = [
            {"ip": "172.28.0.10", "open_ports": [80], "services": ["http"]},
        ]
        state["error_log"] = [
            {"tool_name": "msf_run_exploit", "error_message": "RPC error"},
            {"tool_name": "msf_search_exploits", "error_message": "Connection refused"},
        ]

        rec = compute_strategy(dict(state))
        assert "msf_run_exploit" not in rec.recommended_tools
        assert "msf_search_exploits" not in rec.recommended_tools
        # Should have fallback tools
        assert "nmap_scan" in rec.recommended_tools or "http_get" in rec.recommended_tools

    def test_fallback_approach_on_consec_failures(self) -> None:
        """3+ consecutive failures should trigger fallback_conservative approach."""
        state = initial_state(targets=["172.28.0.10"])
        state["current_phase"] = "exploitation"
        state["consecutive_failures"] = 3

        rec = compute_strategy(dict(state))
        assert rec.approach == "fallback_conservative"

    def test_adaptive_strategy_node_updates_plan(self) -> None:
        """The adaptive_strategy_node should write a plan string to state."""
        state = initial_state(targets=["172.28.0.10"])
        state["current_phase"] = "scanning"
        state["discovered_targets"] = [
            {"ip": "172.28.0.10", "open_ports": [80], "services": ["http"]},
        ]

        result = adaptive_strategy_node(state)
        assert "Strategy" in result["plan"]
        assert "scanning" in result["plan"]

    def test_risk_assessment_near_threshold(self) -> None:
        """Strategy should warn when risk is approaching kill-switch level."""
        state = initial_state(targets=["172.28.0.10"])
        state["current_phase"] = "exploitation"
        state["findings"] = [
            {"severity": "critical"},
            {"severity": "critical"},
            {"severity": "high"},
        ]
        # risk_score must be set in state (strategy reads it, doesn't compute)
        state["risk_score"] = 65.0
        rec = compute_strategy(dict(state))
        assert "ELEVATED" in rec.risk_assessment
