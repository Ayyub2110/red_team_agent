"""Integration tests for the LangGraph agent graph structure."""

from __future__ import annotations

import os

os.environ["ALLOWED_TARGET_SUBNET"] = "172.20.0.0/24"
os.environ["REQUIRE_HUMAN_APPROVAL"] = "false"


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
        ]
        for key in required_keys:
            assert key in state, f"Missing key: {key}"


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
