from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from bench_orchestrator.evidence import RunRecorder
from bench_orchestrator.models import AgentResult, Manifest, RunContext, TargetHandle


class AgentAdapter(ABC):
    name: str

    @property
    def model_name(self) -> str | None:
        return None

    @property
    def compose_file(self) -> Path | None:
        """Path to a docker-compose file that provides infrastructure required by this adapter.

        Returns None if the adapter requires no companion infrastructure.
        """
        return None

    @abstractmethod
    def prepare(self, manifest: Manifest, target: TargetHandle, context: RunContext, recorder: RunRecorder) -> None:
        raise NotImplementedError

    @abstractmethod
    def run(self, manifest: Manifest, target: TargetHandle, context: RunContext, recorder: RunRecorder) -> AgentResult:
        raise NotImplementedError

    def stop(self, recorder: RunRecorder) -> None:
        recorder.event("agent_stopped", {"adapter": self.name})

