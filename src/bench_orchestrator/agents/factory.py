from __future__ import annotations

from pathlib import Path

from bench_orchestrator.agents.base import AgentAdapter
from bench_orchestrator.agents.manual import ManualAgentAdapter
from bench_orchestrator.agents.pentest_agent import PentestAgentAdapter
from bench_orchestrator.agents.vulnbot import VulnBotAdapter


def build_agent_adapter(name: str, pentest_agent_dir: Path | None = None) -> AgentAdapter:
    if name == "manual":
        return ManualAgentAdapter()
    if name == "pentest-agent":
        if pentest_agent_dir is None:
            raise ValueError("--pentest-agent-dir is required for the pentest-agent adapter")
        return PentestAgentAdapter(pentest_agent_dir=pentest_agent_dir)
    if name == "vulnbot":
        return VulnBotAdapter()
    raise ValueError(f"unknown agent adapter: {name}")

