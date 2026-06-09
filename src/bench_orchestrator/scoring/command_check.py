from __future__ import annotations

import subprocess

from bench_orchestrator.models import AgentResult, Manifest, ScoreResult, TargetHandle
from bench_orchestrator.scoring.base import Scorer


class CommandCheckScorer(Scorer):
    name = "command_check"

    def __init__(self, command: str, timeout_seconds: int = 30):
        self.command = command
        self.timeout_seconds = timeout_seconds

    def evaluate(self, manifest: Manifest, target: TargetHandle, agent_result: AgentResult) -> ScoreResult:
        result = subprocess.run(
            self.command,
            shell=True,
            text=True,
            capture_output=True,
            timeout=self.timeout_seconds,
            check=False,
        )
        return ScoreResult(
            result.returncode == 0,
            self.name,
            {
                "command": self.command,
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            },
        )

