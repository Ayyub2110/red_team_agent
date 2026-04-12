"""
Streamlit Web UI for the Red Team Agent.

Features:
- Phase progress visualisation with kill-chain tracker
- Findings heatmap by severity
- Risk trend chart
- Safety compliance score
- Critic / strategy feed
- Mode selection (dynamic / safe / aggressive)

Run with: streamlit run src/ui/app.py
"""

from __future__ import annotations

import json

import streamlit as st
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from src.agent.graph import MODE_PRESETS, run_redteam_agent
from src.agent.state import EXTENDED_PHASES
from src.config import get_settings

st.set_page_config(
    page_title="🔴 Red Team Agent",
    page_icon="🔴",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Premium Dark CSS ────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Outfit', sans-serif;
    }

    .stApp {
        background: linear-gradient(135deg, #050510 0%, #0c0d22 100%);
        color: #e0e0e0;
    }

    .title-banner {
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 16px;
        backdrop-filter: blur(8px);
        padding: 1.5rem;
        text-align: center;
        margin-bottom: 1.5rem;
        box-shadow: 0 4px 30px rgba(0, 0, 0, 0.5);
    }

    .main-header {
        background: linear-gradient(90deg, #ff4c4c, #c0392b);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 2.5rem;
        font-weight: 700;
        margin: 0;
    }

    .sub-header {
        font-size: 1rem;
        color: #888;
        letter-spacing: 2px;
        text-transform: uppercase;
        margin-top: 0.3rem;
    }

    /* Metric Cards */
    .metric-card {
        background: rgba(43, 45, 66, 0.5);
        border-radius: 12px;
        padding: 1rem;
        text-align: center;
        border: 1px solid rgba(255, 255, 255, 0.05);
        transition: 0.3s;
    }
    .metric-card:hover {
        border-color: #ff4c4c;
        background: rgba(43, 45, 66, 0.8);
    }
    .metric-value {
        font-size: 2rem;
        font-weight: bold;
        color: #ff4c4c;
    }
    .metric-label {
        font-size: 0.75rem;
        color: #888;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    /* Phase tracker */
    .phase-tracker {
        display: flex;
        gap: 4px;
        margin: 1rem 0;
    }
    .phase-dot {
        flex: 1;
        height: 8px;
        border-radius: 4px;
        transition: 0.3s;
    }
    .phase-done { background: #2ecc71; }
    .phase-active { background: #ff4c4c; animation: pulse 1.5s infinite; }
    .phase-pending { background: rgba(255,255,255,0.1); }

    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.5; }
    }

    /* Severity badges */
    .sev-critical { color: #ff4c4c; font-weight: bold; }
    .sev-high { color: #e74c3c; }
    .sev-medium { color: #f39c12; }
    .sev-low { color: #3498db; }
    .sev-info { color: #888; }

    /* Chat */
    .chat-bubble {
        padding: 0.8rem 1rem;
        border-radius: 12px;
        margin-bottom: 0.5rem;
        max-width: 90%;
        font-size: 0.9rem;
    }
    .agent-bubble {
        background: rgba(30, 31, 58, 0.9);
        border-left: 3px solid #ff4c4c;
    }
    .user-bubble {
        background: rgba(50, 52, 92, 0.9);
        border-right: 3px solid #3498db;
        margin-left: auto;
        text-align: right;
    }
    .system-bubble {
        background: rgba(100, 100, 100, 0.1);
        font-size: 0.8rem;
        font-style: italic;
        text-align: center;
        margin: 0.5rem auto;
    }

    /* Kill switch banner */
    .kill-switch-banner {
        background: rgba(255, 76, 76, 0.15);
        border: 1px solid #ff4c4c;
        border-radius: 8px;
        padding: 0.8rem;
        text-align: center;
        color: #ff4c4c;
        font-weight: bold;
        margin: 1rem 0;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def _render_phase_tracker(current_phase: str) -> str:
    """Build HTML for the kill-chain phase progress bar."""
    phases = EXTENDED_PHASES
    current_idx = phases.index(current_phase) if current_phase in phases else -1

    dots = []
    for i, phase in enumerate(phases):
        if i < current_idx:
            cls = "phase-done"
        elif i == current_idx:
            cls = "phase-active"
        else:
            cls = "phase-pending"
        dots.append(f'<div class="phase-dot {cls}" title="{phase}"></div>')

    labels = " → ".join(
        f"**{p.title()}**" if p == current_phase else p.replace("_", " ").title()
        for p in phases
    )

    return f"""
    <div class="phase-tracker">{''.join(dots)}</div>
    """


def _severity_color(sev: str) -> str:
    return {
        "critical": "#ff4c4c",
        "high": "#e74c3c",
        "medium": "#f39c12",
        "low": "#3498db",
        "info": "#888",
    }.get(sev, "#888")


def main() -> None:
    """Main Streamlit app."""

    # ── Header ──
    st.markdown(
        """
        <div class="title-banner">
            <p class="main-header">RED TEAM AGENT</p>
            <p class="sub-header">Autonomous AI Offensive Framework</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ── Sidebar ──
    with st.sidebar:
        st.header("⚙️ CONFIGURATION")
        settings = get_settings()

        target_input = st.text_input("🎯 TARGET (IP/CIDR)", value="172.28.0.10")

        mode = st.selectbox("🔧 ENGAGEMENT MODE", ["dynamic", "safe", "aggressive"])

        # Show mode details
        if mode:
            preset = MODE_PRESETS.get(mode, {})
            st.caption(
                f"Aggression: **{preset.get('aggression_level', '?')}** | "
                f"Stealth: **{'on' if preset.get('stealth_mode') else 'off'}** | "
                f"Steps: **{preset.get('max_steps', '?')}**"
            )

        model_name = st.selectbox("🧠 LLM MODEL", [
            settings.llm.ollama_model,
            "qwen2.5-coder:14b",
            "llama3.3",
            "mistral-nemo",
        ])

        st.divider()

        objective = st.text_area(
            "📝 MISSION OBJECTIVE",
            value="Perform reconnaissance and scanning on target 172.28.0.10. Identify all open ports and services.",
            height=100,
        )

        st.divider()

        start_btn = st.button("🚀 INITIATE ENGAGEMENT", type="primary", use_container_width=True)
        st.button("🛑 HALT AGENT", type="secondary", use_container_width=True)

    # ── Dashboard Layout ──
    tab_live, tab_compare = st.tabs(["🚀 Live Dashboard", "📊 Run Comparisons"])
    
    with tab_live:
        col_main, col_intel = st.columns([2, 1])

        agent_state = st.session_state.get("agent_state", {})

        with col_main:
            # ── Top Metrics Row ──
            m1, m2, m3, m4, m5 = st.columns(5)
        with m1:
            st.metric("Steps", agent_state.get("step_count", 0), delta=None)
        with m2:
            findings = agent_state.get("findings", [])
            st.metric("Findings", len(findings))
        with m3:
            risk = agent_state.get("risk_score", 0)
            st.metric("Risk Score", f"{risk:.0f}/100")
        with m4:
            sessions = agent_state.get("active_sessions", {})
            st.metric("Sessions", len(sessions))
        with m5:
            errors = agent_state.get("total_errors", 0)
            st.metric("Errors", errors)

        # ── Phase Tracker ──
        phase = agent_state.get("current_phase", "OFFLINE")
        st.markdown(_render_phase_tracker(phase), unsafe_allow_html=True)
        st.caption(f"📍 Current Phase: **{phase.upper().replace('_', ' ')}**")

        # Kill-switch banner
        if agent_state.get("kill_switch_triggered"):
            st.markdown(
                f'<div class="kill-switch-banner">🛑 KILL SWITCH ACTIVATED — '
                f'{agent_state.get("kill_switch_reason", "Unknown")}</div>',
                unsafe_allow_html=True,
            )

        st.divider()

        # ── Mission Control (Chat) ──
        st.subheader("📡 Mission Control")
        chat_container = st.container(height=400)

        # Run logic
        if start_btn:
            if not target_input:
                st.error("Please specify a target IP.")
            else:
                st.session_state["messages"] = []
                st.session_state["findings"] = []

                with st.spinner("🤖 Agent is thinking..."):
                    try:
                        targets = [t.strip() for t in target_input.split(",")]
                        state_values = run_redteam_agent(
                            objective=objective,
                            targets=targets,
                            mode=mode,
                        )
                        vals = state_values.values if hasattr(state_values, "values") else state_values
                        st.session_state["agent_state"] = vals
                        st.session_state["messages"] = vals.get("messages", [])
                        st.session_state["findings"] = vals.get("findings", [])
                        st.success("✅ Operation complete!")
                        st.rerun()
                    except Exception as exc:
                        st.error(f"❌ Critical Failure: {exc}")

        # Display Chat
        with chat_container:
            history = st.session_state.get("messages", [])
            for msg in history:
                if isinstance(msg, HumanMessage):
                    st.markdown(f'<div class="chat-bubble user-bubble">{msg.content}</div>', unsafe_allow_html=True)
                elif isinstance(msg, AIMessage):
                    if msg.content:
                        st.markdown(f'<div class="chat-bubble agent-bubble">{msg.content[:500]}</div>', unsafe_allow_html=True)
                    if hasattr(msg, "tool_calls") and msg.tool_calls:
                        for tool in msg.tool_calls:
                            st.markdown(f'<div class="chat-bubble system-bubble">🔧 Tool: {tool["name"]}</div>', unsafe_allow_html=True)

    # ── Right Column: Intelligence ──
    with col_intel:
        st.subheader("🔍 Intelligence Dashboard")

        # ── Findings Heatmap ──
        st.markdown("#### 🧬 Findings by Severity")
        findings = st.session_state.get("findings", [])
        if findings:
            severity_counts = {}
            for f in findings:
                sev = f.get("severity", "info")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            for sev in ["critical", "high", "medium", "low", "info"]:
                count = severity_counts.get(sev, 0)
                if count > 0:
                    bar_width = min(count * 20, 100)
                    color = _severity_color(sev)
                    st.markdown(
                        f'<div style="display:flex;align-items:center;margin:4px 0;">'
                        f'<span style="width:70px;font-size:0.8rem;color:{color};text-transform:uppercase;">{sev}</span>'
                        f'<div style="flex:1;background:rgba(255,255,255,0.05);border-radius:4px;height:20px;overflow:hidden;">'
                        f'<div style="width:{bar_width}%;height:100%;background:{color};border-radius:4px;'
                        f'transition:width 0.5s;"></div></div>'
                        f'<span style="width:30px;text-align:right;font-size:0.85rem;color:{color};">{count}</span>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )
        else:
            st.caption("No findings yet.")

        st.divider()

        # ── Safety Compliance ──
        st.markdown("#### 🛡️ Safety Compliance")
        kill_switch = agent_state.get("kill_switch_triggered", False)
        total_err = agent_state.get("total_errors", 0)
        consec_fail = agent_state.get("consecutive_failures", 0)

        # Simple compliance score
        compliance = 100
        if kill_switch:
            compliance -= 30
        compliance -= min(total_err * 5, 40)
        compliance = max(compliance, 0)

        st.progress(compliance / 100, text=f"Compliance: {compliance}%")
        if kill_switch:
            st.error("🛑 Kill switch was triggered")
        elif total_err > 0:
            st.warning(f"⚠️ {total_err} error(s) during engagement")
        else:
            st.success("✅ Clean engagement")

        st.divider()

        # ── Strategy Feed ──
        st.markdown("#### 🧠 Strategy Feed")
        strategy_hist = agent_state.get("strategy_history", [])
        if strategy_hist:
            for entry in reversed(strategy_hist[-5:]):
                dec = entry.get("decision", "?")
                reason = entry.get("reasoning", "")[:80]
                risk_val = entry.get("risk_score_at_time", 0)
                icon = "🛑" if "KILL" in dec else "🧠"
                st.markdown(
                    f"**{icon} {dec}** (risk={risk_val:.0f})\n\n"
                    f"_{reason}_"
                )
                st.markdown("---")
        else:
            st.caption("No strategic decisions yet.")

        # ── Critic Feedback ──
        critic_fb = agent_state.get("critic_feedback", [])
        if critic_fb:
            st.markdown("#### 🔍 Critic Observations")
            for fb in reversed(critic_fb[-3:]):
                severity = fb.get("severity", "info")
                icon = "🔴" if severity == "critical" else "🟡"
                st.markdown(
                    f"{icon} **{fb.get('issue', '?')}**\n\n"
                    f"_{fb.get('suggestion', '')}_"
                )
                st.markdown("---")

        # ── Detailed Findings ──
        st.divider()
        st.markdown("#### 📋 Detailed Findings")
        if findings:
            for f in findings:
                vuln = f.get("vulnerability", f.get("vuln_type", "Discovery"))
                target = f.get("target", "Unknown")
                sev = f.get("severity", "info")
                conf = f.get("confidence", 0)
                with st.expander(f"🔴 {vuln} — {target}"):
                    st.write(f"**Severity:** {sev.upper()}")
                    st.write(f"**Confidence:** {conf:.0%}" if conf else "**Confidence:** N/A")
                    st.write(f"**Evidence:** {f.get('evidence', 'None')}")
                    if f.get("remediation"):
                        st.code(f.get("remediation", ""), language="text")
        else:
            st.caption("No findings reported yet.")

    with tab_compare:
        st.subheader("📊 Cross-Run Comparisons")
        from pathlib import Path
        import os
        
        report_dir = Path("logs/evaluation_reports")
        if report_dir.exists() and any(report_dir.iterdir()):
            st.success(f"Found {len(list(report_dir.glob('*.md')))} evaluation reports.")
            reports = list(report_dir.glob("*.md"))
            selected_report = st.selectbox("Select Report", [r.name for r in reports])
            if selected_report:
                report_content = (report_dir / selected_report).read_text()
                st.markdown(report_content)
        else:
            st.info("No comparative evaluations found. Run `poetry run redteam evaluate --compare-modes` to generate comparisons.")

if __name__ == "__main__":
    main()
