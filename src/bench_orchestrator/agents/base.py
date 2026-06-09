from __future__ import annotations

from abc import ABC, abstractmethod

from bench_orchestrator.evidence import RunRecorder
from bench_orchestrator.models import AgentResult, Manifest, RunContext, TargetHandle


class AgentAdapter(ABC):
    name: str

    @abstractmethod
    def prepare(self, manifest: Manifest, target: TargetHandle, context: RunContext, recorder: RunRecorder) -> None:
        raise NotImplementedError

    @abstractmethod
    def run(self, manifest: Manifest, target: TargetHandle, context: RunContext, recorder: RunRecorder) -> AgentResult:
        raise NotImplementedError

    def stop(self, recorder: RunRecorder) -> None:
        recorder.event("agent_stopped", {"adapter": self.name})

