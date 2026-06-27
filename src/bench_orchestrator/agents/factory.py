from __future__ import annotations

from pathlib import Path

from bench_orchestrator.agents.base import AgentAdapter
from bench_orchestrator.agents.manual import ManualAgentAdapter
from bench_orchestrator.agents.pentest_agent import PentestAgentAdapter
from bench_orchestrator.agents.pentestgptv2 import PentestGptV2Adapter
from bench_orchestrator.agents.vulnbot import VulnBotAdapter


def build_agent_adapter(
    name: str,
    pentest_agent_dir: Path | None = None,
    pentestgptv2_image: str = "pentestgpt:latest",
    vulnbot_image: str = "ghcr.io/roughscale/vulnbot:latest",
) -> AgentAdapter:
    if name == "manual":
        return ManualAgentAdapter()
    if name == "pentest-agent":
        if pentest_agent_dir is None:
            raise ValueError("--pentest-agent-dir is required for the pentest-agent adapter")
        return PentestAgentAdapter(pentest_agent_dir=pentest_agent_dir)
    if name in {"pentestgptv2", "pentestgpt-v2", "pentestgpt"}:
        return PentestGptV2Adapter(image=pentestgptv2_image)
    if name == "vulnbot":
        return VulnBotAdapter(image=vulnbot_image)
    raise ValueError(f"unknown agent adapter: {name}")
