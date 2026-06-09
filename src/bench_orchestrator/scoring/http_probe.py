from __future__ import annotations

import requests

from bench_orchestrator.models import AgentResult, Manifest, ScoreResult, TargetHandle
from bench_orchestrator.scoring.base import Scorer


class HttpProbeScorer(Scorer):
    name = "http_probe"

    def __init__(self, url: str, expect_status: list[int] | None = None, timeout_seconds: int = 10):
        self.url = url
        self.expect_status = expect_status or [200, 302]
        self.timeout_seconds = timeout_seconds

    def evaluate(self, manifest: Manifest, target: TargetHandle, agent_result: AgentResult) -> ScoreResult:
        try:
            response = requests.get(self.url, timeout=self.timeout_seconds)
        except requests.RequestException as exc:
            return ScoreResult(False, self.name, {"url": self.url, "error": str(exc)}, "HTTP probe failed")
        passed = response.status_code in self.expect_status
        return ScoreResult(
            passed,
            self.name,
            {"url": self.url, "status_code": response.status_code, "expect_status": self.expect_status},
        )

