"""
LangGraph implementation for the Autonomous AI Red Team Agent.

Uses a ReAct loop (reason -> act -> observe) with dynamic system prompt 
injection and persistent memory using LangGraph 1.x.
"""

from typing import Literal, Any
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import create_react_agent
from langgraph.checkpoint.memory import MemorySaver

from src.agent.state import AgentState
from src.agent.prompts import build_system_prompt
from src.tools import tools as all_tools
from src.config import get_settings


def build_redteam_graph(model: Any) -> StateGraph:
    """
    Builds and compiles the red teaming agent graph.
    
    Args:
        model: A chat model (e.g. ChatOllama) to drive the agent reasoning.
    """

    # System prompt function that injects dynamic state into the prompt template
    def get_system_prompt(state: AgentState) -> list:
        prompt = build_system_prompt(dict(state), max_steps=state.get("max_steps", 15))
        return [SystemMessage(content=prompt)]

    # We use a custom graph structure because we may want to add advanced phases later.
    # 1. Create the core logic (ReAct agent)
    agent = create_react_agent(
        model=model,
        tools=all_tools,
        state_modifier=get_system_prompt,   # Injects dynamic safety/phase info
        checkpointer=MemorySaver(),         # Enables session memory
    )

    # 2. Add an explicit 'agent' node to a new graph builder
    builder = StateGraph(AgentState)
    builder.add_node("redteam_agent", agent)

    # 3. Simple flow: Entry -> Agent -> End (Agent handles internally the tool loop)
    builder.add_edge(START, "redteam_agent")
    builder.add_edge("redteam_agent", END)

    # 4. Compile with memory
    return builder.compile(checkpointer=MemorySaver())


def run_redteam_agent(
    objective: str, 
    targets: list[str], 
    max_steps: int = 15,
    thread_id: str = "redteam-session-1"
):
    """
    High-level entry point to execute the agent for a specific objective.
    """
    settings = get_settings()
    
    # Initialize the LLM (Ollama)
    model = ChatOllama(
        base_url=settings.llm.ollama_base_url,
        model=settings.llm.ollama_model,
        temperature=settings.llm.temperature,
    )
    
    # Prepare initial state
    initial_input: AgentState = {
        "messages": [HumanMessage(content=objective)],
        "current_phase": "recon",
        "findings": [],
        "step_count": 0,
        "max_steps": max_steps,
        "approved_actions": [],
        "allowed_subnet": settings.safety.allowed_target_subnet,
        "targets": targets,
    }

    config = {"configurable": {"thread_id": thread_id}}
    graph = build_redteam_graph(model=model)
    
    # Stream for visibility in CLI/UI applications
    print(f"\n🚀 Engagement started: {objective}\n")
    for chunk in graph.stream(initial_input, config, stream_mode="updates"):
        # We can extract messages from the chunk to show incremental output
        if "redteam_agent" in chunk:
            msg = chunk["redteam_agent"]["messages"][-1]
            if hasattr(msg, "content") and msg.content:
                print(f"[Agent]: {msg.content[:500]}...")
    
    return graph.get_state(config)