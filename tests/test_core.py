"""Tests for safety guardrails — the most critical component."""

from __future__ import annotations

import pytest

# Set test environment before importing modules
# os.environ["ALLOWED_TARGET_SUBNET"] = "0.0.0.0/0"
# os.environ["REQUIRE_HUMAN_APPROVAL"] = "false"


@pytest.fixture(autouse=True)
def reset_settings():
    """Reset the settings singleton before each test."""
    from src import config
    config._settings = None
    yield
    config._settings = None


class TestTargetValidation:
    """Ensure targets outside the allowed subnet are always rejected."""

    def test_valid_target_in_subnet(self) -> None:
        """Target inside 172.28.0.0/16 should pass."""
        from src.guardrails import validate_target

        # Should not raise
        validate_target("172.28.0.10")
        validate_target("172.28.0.255")
        validate_target("172.28.0.1")

    def test_allow_any_ip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """With 0.0.0.0/0, everything should pass."""
        monkeypatch.setenv("ALLOWED_TARGET_SUBNET", "0.0.0.0/0")
        from src.guardrails import validate_target

        # External, internal, and local IPs should all be allowed now
        validate_target("8.8.8.8")
        validate_target("172.28.0.10")
        validate_target("192.168.1.1")
        validate_target("10.0.0.1")

    def test_cidr_target_accepted(self) -> None:
        """CIDR notation should validate the network portion."""
        from src.guardrails import validate_target

        validate_target("172.28.0.0/16")

    def test_unresolvable_hostname_rejected(self) -> None:
        """Hostnames that cannot be resolved should be rejected."""
        from src.guardrails import TargetValidationError, validate_target

        with pytest.raises(TargetValidationError, match="Cannot resolve"):
            validate_target("this-host-does-not-exist-12345.invalid")


class TestBlockedCommands:
    """Ensure dangerous shell commands are blocked."""

    def test_blocked_rm_rf(self) -> None:
        from src.guardrails import TargetValidationError, check_blocked_commands

        with pytest.raises(TargetValidationError, match="blocked pattern"):
            check_blocked_commands("rm -rf /")

    def test_blocked_fork_bomb(self) -> None:
        from src.guardrails import TargetValidationError, check_blocked_commands

        with pytest.raises(TargetValidationError, match="blocked pattern"):
            check_blocked_commands(":(){:|:&};:")

    def test_safe_command_allowed(self) -> None:
        from src.guardrails import check_blocked_commands

        # Should not raise
        check_blocked_commands("nmap -sV 172.28.0.10")
        check_blocked_commands("ls -la")


class TestAgentState:
    """Verify agent state initialization and structure."""

    def test_initial_state(self) -> None:
        from src.agent.state import initial_state

        state = initial_state()

        assert state["current_phase"] == "reconnaissance"
        assert state["step_count"] == 0
        assert state["targets"] == []
        assert state["findings"] == []
        assert state["sessions"] == []
        assert state["messages"] == []
        # New fields
        assert state["risk_score"] == 0.0
        assert state["discovered_targets"] == []
        assert state["active_sessions"] == {}
        assert state["strategy_history"] == []
        assert state["aggression_level"] == "medium"
        assert state["stealth_mode"] is False
        # Error tracking fields
        assert state["error_log"] == []
        assert state["phase_failures"] == {}
        assert state["consecutive_failures"] == 0
        assert state["total_errors"] == 0
        assert state["kill_switch_triggered"] is False
        assert state["kill_switch_reason"] == ""
        assert state["critic_feedback"] == []
        assert state["last_successful_phase"] == ""

    def test_initial_state_custom_params(self) -> None:
        from src.agent.state import initial_state

        state = initial_state(
            targets=["172.28.0.10"],
            max_steps=25,
            aggression_level="low",
            stealth_mode=True,
        )
        assert state["aggression_level"] == "low"
        assert state["stealth_mode"] is True
        assert state["max_steps"] == 25
        assert state["targets"] == ["172.28.0.10"]

    def test_finding_dataclass(self) -> None:
        from src.agent.state import Finding

        finding = Finding(
            target="172.28.0.10",
            port=80,
            service="http",
            vulnerability="SQL Injection in login form",
            severity="critical",
            evidence="Parameter 'id' is injectable",
            remediation="Use parameterized queries",
            cve="CVE-2021-XXXX",
            confidence=0.95,
        )

        d = finding.to_dict()
        assert d["target"] == "172.28.0.10"
        assert d["severity"] == "critical"
        assert d["exploited"] is False
        assert d["confidence"] == 0.95

    def test_risk_score_calculation(self) -> None:
        from src.agent.state import calculate_risk_score

        findings = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "low"},
        ]
        score = calculate_risk_score(findings)
        # critical=25 + high=15 + low=3 = 43
        assert score == 43.0

    def test_risk_score_caps_at_100(self) -> None:
        from src.agent.state import calculate_risk_score

        findings = [{"severity": "critical"} for _ in range(10)]
        score = calculate_risk_score(findings)
        assert score == 100.0

    def test_engagement_success_score(self) -> None:
        from src.agent.state import calculate_engagement_success, initial_state

        state = initial_state(targets=["172.28.0.10"])
        state["discovered_targets"] = [{"ip": "172.28.0.10"}]
        state["findings"] = [{"severity": "critical"}]
        state["current_phase"] = "exploitation"

        result = calculate_engagement_success(state)
        assert "overall" in result
        assert result["discovery_rate"] == 100.0
        assert result["overall"] > 0

    def test_error_record_dataclass(self) -> None:
        from src.agent.state import ErrorRecord

        err = ErrorRecord(
            phase="exploitation",
            tool_name="msf_run_exploit",
            error_message="Connection refused",
            retry_count=2,
        )
        d = err.to_dict()
        assert d["phase"] == "exploitation"
        assert d["retry_count"] == 2
        assert d["recovered"] is False

    def test_kill_switch_thresholds_exist(self) -> None:
        from src.agent.state import (
            KILL_SWITCH_ERROR_THRESHOLD,
            KILL_SWITCH_RISK_THRESHOLD,
            MAX_CONSECUTIVE_FAILURES,
        )

        assert KILL_SWITCH_RISK_THRESHOLD == 80
        assert KILL_SWITCH_ERROR_THRESHOLD == 10
        assert MAX_CONSECUTIVE_FAILURES == 3


class TestConfig:
    """Verify configuration loading."""

    def test_default_settings(self) -> None:
        from src.config import Settings

        settings = Settings()
        assert settings.safety.max_agent_steps == 50
        assert settings.safety.require_human_approval is True
        assert "172.28.0.0/16" in settings.safety.allowed_target_subnet

    def test_blocked_commands_default(self) -> None:
        from src.config import Settings

        settings = Settings()
        assert "rm -rf /" in settings.safety.blocked_commands


class TestAuditLogger:
    """Verify audit logging writes correct entries."""

    def test_audit_record_creates_file(self, tmp_path) -> None:
        import json

        from src.logging import AuditLogger

        log_file = tmp_path / "test_audit.jsonl"
        logger = AuditLogger(log_file)

        logger.record(
            "test_event",
            tool="nmap",
            target="172.28.0.10",
            risk_level="low",
        )

        assert log_file.exists()
        entries = [json.loads(line) for line in log_file.read_text().strip().split("\n")]
        assert len(entries) == 1
        assert entries[0]["event"] == "test_event"
        assert entries[0]["tool"] == "nmap"
        assert entries[0]["target"] == "172.28.0.10"

    def test_audit_multiple_records(self, tmp_path) -> None:
        import json

        from src.logging import AuditLogger

        log_file = tmp_path / "test_audit2.jsonl"
        logger = AuditLogger(log_file)

        for i in range(5):
            logger.record(f"event_{i}", tool="test")

        entries = [json.loads(line) for line in log_file.read_text().strip().split("\n")]
        assert len(entries) == 5


class TestPrompts:
    """Verify prompt template rendering."""

    def test_system_prompt_renders(self) -> None:
        from src.agent.prompts import build_system_prompt

        state = {
            "current_phase": "scanning",
            "step_count": 5,
            "targets": [{"ip": "172.28.0.10"}],
            "findings": [{"severity": "high"}, {"severity": "medium"}],
            "sessions": [],
            "risk_score": 23.0,
            "discovered_targets": [{"ip": "172.28.0.10"}],
            "active_sessions": {},
            "strategy_history": [],
            "aggression_level": "medium",
            "stealth_mode": False,
        }

        prompt = build_system_prompt(state)
        assert "scanning" in prompt.lower()
        # The default settings use 172.28.0.0/16
        assert "172.28.0.0/16" in prompt
        assert "2 finding(s)" in prompt
        assert "Step**: 5" in prompt
        assert "Risk Score**: 23.0" in prompt
        assert "Think like an experienced red teamer" in prompt

    def test_stealth_mode_in_prompt(self) -> None:
        from src.agent.prompts import build_system_prompt

        state = {
            "current_phase": "reconnaissance",
            "step_count": 0,
            "findings": [],
            "risk_score": 0,
            "discovered_targets": [],
            "active_sessions": {},
            "strategy_history": [],
            "aggression_level": "medium",
            "stealth_mode": True,
        }
        prompt = build_system_prompt(state)
        assert "STEALTH MODE" in prompt
        assert "Stealth Mode**: ON" in prompt
