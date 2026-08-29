from __future__ import annotations

from pathlib import Path

from bench_orchestrator.agents.base import AgentAdapter
from bench_orchestrator.agents.cai_agent import CaiAgentAdapter
from bench_orchestrator.agents.manual import ManualAgentAdapter
from bench_orchestrator.agents.pentest_agent import PentestAgentAdapter
from bench_orchestrator.agents.vulnbot import VulnBotAdapter


def build_agent_adapter(
    name: str,
    pentest_agent_dir: Path | None = None,
    agent_config: dict | None = None,
    image: str | None = None,
) -> AgentAdapter:
    """Build the named adapter.

    `image` is the one Docker image knob every container-based adapter has -
    resolved from (in order) the CLI's --agent-image, the agent config's
    "image" key, then that adapter's own default, so it's set in one place
    per run rather than one CLI flag per adapter.
    """
    agent_config = agent_config or {}
    resolved_image = image or agent_config.get("image")

    if name == "manual":
        return ManualAgentAdapter()
    if name == "pentest-agent":
        if pentest_agent_dir is None:
            raise ValueError("--pentest-agent-dir is required for the pentest-agent adapter")
        return PentestAgentAdapter(
            pentest_agent_dir=pentest_agent_dir,
            image=resolved_image or "pentest-agent:latest",
            agent_config=agent_config,
        )
    if name == "vulnbot":
        return VulnBotAdapter(image=resolved_image or "vulnbot:latest", agent_config=agent_config)
    if name == "cai":
        return CaiAgentAdapter(image=resolved_image or "cai-bench:latest", agent_config=agent_config)
    raise ValueError(f"unknown agent adapter: {name}")

