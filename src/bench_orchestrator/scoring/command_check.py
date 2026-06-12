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
        container_id = target.metadata.get("primary_container_id")
        if container_id:
            result = self._docker_exec(container_id)
        else:
            result = self._local_exec()

        return ScoreResult(
            result.returncode == 0,
            self.name,
            {
                "command": self.command,
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "via": "docker_exec" if container_id else "local",
            },
        )

    def _docker_exec(self, container_id: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["docker", "exec", container_id, "sh", "-c", self.command],
            text=True,
            capture_output=True,
            timeout=self.timeout_seconds,
            check=False,
        )

    def _local_exec(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self.command,
            shell=True,
            text=True,
            capture_output=True,
            timeout=self.timeout_seconds,
            check=False,
        )

