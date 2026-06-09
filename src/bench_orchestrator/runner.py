from __future__ import annotations

from pathlib import Path

from bench_orchestrator.agents.base import AgentAdapter
from bench_orchestrator.evidence import RunRecorder
from bench_orchestrator.models import Manifest, RunContext, ScoreResult
from bench_orchestrator.scoring.base import Scorer
from bench_orchestrator.targets.base import TargetProvider


class BenchmarkRunner:
    def __init__(
        self,
        target_provider: TargetProvider,
        agent_adapter: AgentAdapter,
        scorers: list[Scorer],
        *,
        root_dir: Path,
        dry_run: bool = False,
    ):
        self.target_provider = target_provider
        self.agent_adapter = agent_adapter
        self.scorers = scorers
        self.root_dir = root_dir
        self.dry_run = dry_run

    def run_task(self, manifest: Manifest) -> list[ScoreResult]:
        context = RunContext.create(self.root_dir, dry_run=self.dry_run)
        recorder = RunRecorder(context)
        recorder.initialize(
            {
                "manifest": manifest.raw,
                "target_provider": self.target_provider.name,
                "agent_adapter": self.agent_adapter.name,
            }
        )
        handle = None
        try:
            self.target_provider.prepare(manifest, context, recorder)
            handle = self.target_provider.start(manifest, context, recorder)
            health = self.target_provider.healthcheck(handle, manifest, recorder)
            if not health.ready:
                raise RuntimeError(f"target not healthy: {health.message}")
            self.agent_adapter.prepare(manifest, handle, context, recorder)
            result = self.agent_adapter.run(manifest, handle, context, recorder)
            scores = [scorer.evaluate(manifest, handle, result) for scorer in self.scorers]
            recorder.score(scores)
            return scores
        except Exception as exc:
            recorder.event("failed", {"error": str(exc)})
            raise
        finally:
            if handle is not None:
                self.target_provider.collect_logs(handle, manifest, recorder)
                self.target_provider.stop(handle, manifest, recorder)

