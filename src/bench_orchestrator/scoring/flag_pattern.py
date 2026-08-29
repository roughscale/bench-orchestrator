from __future__ import annotations

import re
from pathlib import Path

from bench_orchestrator.models import AgentResult, Manifest, ScoreResult, TargetHandle
from bench_orchestrator.scoring.base import Scorer


class FlagPatternScorer(Scorer):
    """Match agent output against a flag regex instead of one known value.

    FlagScorer needs the expected flag baked into the manifest ahead of
    time, which doesn't fit a target like an HTB machine, where the flag is
    generated fresh on every spawn/reset and isn't knowable when the
    manifest is authored. Mirrors cai's own bench harness
    (CHALLENGE_FLAG_PATTERN), which solves the same problem the same way.
    """

    name = "flag_pattern"

    def __init__(self, pattern: str):
        self.pattern = re.compile(pattern)

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
        match = self.pattern.search(haystack)
        return ScoreResult(match is not None, self.name, {"matched_flag": match.group(0) if match else None})
