from __future__ import annotations

from abc import ABC, abstractmethod

from bench_orchestrator.models import AgentResult, Manifest, ScoreResult, TargetHandle


class Scorer(ABC):
    name: str

    @abstractmethod
    def evaluate(self, manifest: Manifest, target: TargetHandle, agent_result: AgentResult) -> ScoreResult:
        raise NotImplementedError

