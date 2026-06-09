from __future__ import annotations

from bench_orchestrator.agents.base import AgentAdapter
from bench_orchestrator.evidence import RunRecorder
from bench_orchestrator.models import AgentResult, Manifest, RunContext, TargetHandle


class VulnBotAdapter(AgentAdapter):
    name = "vulnbot"

    def prepare(self, manifest: Manifest, target: TargetHandle, context: RunContext, recorder: RunRecorder) -> None:
        recorder.event("agent_prepared", {"adapter": self.name, "status": "future"})

    def run(self, manifest: Manifest, target: TargetHandle, context: RunContext, recorder: RunRecorder) -> AgentResult:
        recorder.event("agent_started", {"adapter": self.name})
        return AgentResult(status="failed", summary="VulnBot adapter is not implemented yet.")

