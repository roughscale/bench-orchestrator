from __future__ import annotations

from pathlib import Path

from bench_orchestrator.models import AgentResult, Manifest, ScoreResult, TargetHandle
from bench_orchestrator.scoring.base import Scorer


class FlagScorer(Scorer):
    name = "flag"

    def __init__(self, expected_flag: str):
        self.expected_flag = expected_flag

    def evaluate(self, manifest: Manifest, target: TargetHandle, agent_result: AgentResult) -> ScoreResult:
        parts = [agent_result.summary]
        for artifact in agent_result.artifacts:
            path = Path(artifact)
            if path.is_file():
                try:
                    parts.append(path.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    parts.append(artifact)
            else:
                parts.append(artifact)
        haystack = "\n".join(parts)
        passed = self.expected_flag in haystack
        return ScoreResult(passed, self.name, {"expected_flag_found": passed})

