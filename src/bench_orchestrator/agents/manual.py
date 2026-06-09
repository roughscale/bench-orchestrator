from __future__ import annotations

from bench_orchestrator.agents.base import AgentAdapter
from bench_orchestrator.evidence import RunRecorder
from bench_orchestrator.models import AgentResult, Manifest, RunContext, TargetHandle


class ManualAgentAdapter(AgentAdapter):
    name = "manual"

    def prepare(self, manifest: Manifest, target: TargetHandle, context: RunContext, recorder: RunRecorder) -> None:
        recorder.event("agent_prepared", {"adapter": self.name})

    def run(self, manifest: Manifest, target: TargetHandle, context: RunContext, recorder: RunRecorder) -> AgentResult:
        recorder.event("agent_started", {"adapter": self.name})
        recorder.event("agent_completed", {"adapter": self.name, "status": "manual_baseline"})
        return AgentResult(status="needs_input", summary="Manual adapter does not execute unattended.")

