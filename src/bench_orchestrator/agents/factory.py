from __future__ import annotations

from bench_orchestrator.agents.base import AgentAdapter
from bench_orchestrator.agents.manual import ManualAgentAdapter
from bench_orchestrator.agents.pentest_agent import PentestAgentAdapter
from bench_orchestrator.agents.vulnbot import VulnBotAdapter


def build_agent_adapter(name: str) -> AgentAdapter:
    if name == "manual":
        return ManualAgentAdapter()
    if name == "pentest-agent":
        return PentestAgentAdapter()
    if name == "vulnbot":
        return VulnBotAdapter()
    raise ValueError(f"unknown agent adapter: {name}")

