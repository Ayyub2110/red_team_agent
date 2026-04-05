"""
Streamlit Web UI for the Red Team Agent.

Run with: streamlit run src/ui/app.py
"""

from __future__ import annotations

import json
from pathlib import Path

import streamlit as st
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from src.agent.graph import run_redteam_agent
from src.config import get_settings

st.set_page_config(
    page_title="🔴 Red Team Agent",
    page_icon="🔴",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS for Premium Design ──
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

    /* Glassmorphism Title */
    .title-banner {
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 16px;
        backdrop-filter: blur(8px);
        padding: 1.5rem;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 4px 30px rgba(0, 0, 0, 0.5);
    }

    .main-header {
        background: linear-gradient(90deg, #ff4c4c, #c0392b);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 3rem;
        font-weight: 700;
        margin: 0;
    }

    .sub-header {
        font-size: 1.1rem;
        color: #888;
        letter-spacing: 2px;
        text-transform: uppercase;
        margin-top: 0.5rem;
    }

    /* Custom Status Cards */
    .status-card {
        background: rgba(43, 45, 66, 0.5);
        border-radius: 12px;
        padding: 1rem;
        border: 1px solid rgba(255, 255, 255, 0.05);
        transition: 0.3s;
    }

    .status-card:hover {
        border-color: #ff4c4c;
        background: rgba(43, 45, 66, 0.8);
    }

    .indicator {
        height: 8px;
        border-radius: 4px;
        background: #ff4c4c;
        margin-top: 5px;
    }

    /* Chat Bubbles */
    .chat-bubble {
        padding: 1rem;
        border-radius: 16px;
        margin-bottom: 0.5rem;
        max-width: 85%;
        font-size: 0.95rem;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }

    .agent-bubble {
        background: rgba(30, 31, 58, 0.9);
        border-left: 4px solid #ff4c4c;
        margin-right: auto;
    }

    .user-bubble {
        background: rgba(50, 52, 92, 0.9);
        border-right: 4px solid #3498db;
        margin-left: auto;
        text-align: right;
    }

    .system-bubble {
        background: rgba(100, 100, 100, 0.1);
        font-size: 0.85rem;
        font-style: italic;
        text-align: center;
        margin: 1rem auto;
        border: none;
    }
    
    /* Metrics display */
    .metric-container {
        display: flex;
        justify-content: space-between;
        margin-bottom: 2rem;
    }
    .metric-box {
        text-align: center;
        flex: 1;
        padding: 1rem;
        background: rgba(255,255,255,0.03);
        border-radius: 10px;
        margin: 0 5px;
    }
    .metric-value {
        font-size: 1.8rem;
        font-weight: bold;
        color: #ff4c4c;
    }
    .metric-label {
        font-size: 0.8rem;
        color: #888;
        text-transform: uppercase;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


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
        
        # Pull defaults from config
        settings = get_settings()
        
        target_input = st.text_input("🎯 TARGET (IP/CIDR)", value="172.20.0.10")
        model_name = st.selectbox("🧠 LLM MODEL", [
            settings.llm.ollama_model, 
            "qwen2.5-coder:14b", 
            "llama3.3", 
            "mistral-nemo"
        ])
        max_steps = st.slider("⏱️ MAX STEPS", min_value=5, max_value=50, value=15)
        
        st.divider()
        
        objective = st.text_area(
            "📝 MISSION OBJECTIVE",
            value="Perform reconnaissance and scanning on target 172.20.0.10. Identify all open ports and services.",
            height=100,
        )

        st.divider()

        start_btn = st.button("🚀 INITIATE ENGAGEMENT", type="primary", use_container_width=True)
        interrupt_btn = st.button("🛑 HALT AGENT", type="secondary", use_container_width=True)

    # ── Dashboard Layout ──
    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("📡 Mission Control")
        
        # Placeholder for messages
        chat_container = st.container(height=500)

        # Run logic
        if start_btn:
            if not target_input:
                st.error("Please specify a target IP.")
            else:
                # Store in session state
                st.session_state["messages"] = []
                st.session_state["findings"] = []
                
                with st.spinner("🤖 Agent is thinking..."):
                    try:
                        # Prepare targets list
                        targets = [target_input]
                        
                        # Execute the agent
                        # For a real UI, you would stream this, but we'll start with blocking call for MVP
                        # we can also update st.session_state as we stream.
                        state_values = run_redteam_agent(
                            objective=objective,
                            targets=targets,
                            max_steps=max_steps
                        ).get("values", {})
                        
                        st.session_state["agent_state"] = state_values
                        st.session_state["messages"] = state_values.get("messages", [])
                        st.session_state["findings"] = state_values.get("findings", [])
                        
                        st.success("✅ Operation complete!")
                    except Exception as exc:
                        st.error(f"❌ Critical Failure: {exc}")

        # Display Chat History
        with chat_container:
            history = st.session_state.get("messages", [])
            for msg in history:
                if isinstance(msg, HumanMessage):
                    st.markdown(f'<div class="chat-bubble user-bubble">{msg.content}</div>', unsafe_allow_html=True)
                elif isinstance(msg, AIMessage):
                    if msg.content:
                        st.markdown(f'<div class="chat-bubble agent-bubble">{msg.content}</div>', unsafe_allow_html=True)
                    if msg.tool_calls:
                        for tool in msg.tool_calls:
                            st.markdown(f'<div class="chat-bubble system-bubble">Executing Tool: {tool["name"]}</div>', unsafe_allow_html=True)
                elif isinstance(msg, SystemMessage):
                    st.markdown(f'<div class="chat-bubble system-bubble">{msg.content}</div>', unsafe_allow_html=True)

    with col2:
        st.subheader("🔍 Intelligence")
        
        # Current state display
        agent_state = st.session_state.get("agent_state", {})
        
        st.markdown(
            f"""
            <div class="metric-container">
                <div class="metric-box">
                    <div class="metric-value">{agent_state.get('step_count', 0)}</div>
                    <div class="metric-label">Steps</div>
                </div>
                <div class="metric-box">
                    <div class="metric-value">{len(st.session_state.get('findings', []))}</div>
                    <div class="metric-label">Findings</div>
                </div>
            </div>
            """, 
            unsafe_allow_html=True
        )
        
        phase = agent_state.get("current_phase", "OFFLINE")
        st.info(f"📍 ACTIVE PHASE: {phase.upper()}")
        
        # Findings List
        st.markdown("### 🧬 Findings")
        findings = st.session_state.get("findings", [])
        if not findings:
            st.write("No findings reported yet.")
        else:
            for f in findings:
                with st.expander(f"🔴 {f.get('vuln_type', 'Discovery')} - {f.get('target', 'Generic')}"):
                    st.write(f"**Severity:** {f.get('severity', 'Unknown')}")
                    st.write(f"**Evidence:** {f.get('evidence', 'No data')}")
                    st.code(f.get('remediation', 'N/A'), language="text")

if __name__ == "__main__":
    main()
