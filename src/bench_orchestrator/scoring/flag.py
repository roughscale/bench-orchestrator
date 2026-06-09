from __future__ import annotations

from bench_orchestrator.models import AgentResult, Manifest, ScoreResult, TargetHandle
from bench_orchestrator.scoring.base import Scorer


class FlagScorer(Scorer):
    name = "flag"

    def __init__(self, expected_flag: str):
        self.expected_flag = expected_flag

    def evaluate(self, manifest: Manifest, target: TargetHandle, agent_result: AgentResult) -> ScoreResult:
        haystack = "\n".join([agent_result.summary, *agent_result.artifacts])
        passed = self.expected_flag in haystack
        return ScoreResult(passed, self.name, {"expected_flag_found": passed})

