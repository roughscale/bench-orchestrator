from __future__ import annotations

from bench_orchestrator.models import AgentResult, Manifest, ScoreResult, TargetHandle
from bench_orchestrator.scoring.base import Scorer


class StageMilestoneScorer(Scorer):
    name = "stage_milestones"

    def __init__(self, required: list[str]):
        self.required = required

    def evaluate(self, manifest: Manifest, target: TargetHandle, agent_result: AgentResult) -> ScoreResult:
        completed = set(agent_result.metadata.get("completed_milestones", []))
        missing = [milestone for milestone in self.required if milestone not in completed]
        return ScoreResult(not missing, self.name, {"required": self.required, "missing": missing})

