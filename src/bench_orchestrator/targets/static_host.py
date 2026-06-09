from __future__ import annotations

from bench_orchestrator.evidence import RunRecorder
from bench_orchestrator.models import HealthStatus, Manifest, RunContext, TargetHandle
from bench_orchestrator.targets.base import TargetProvider


class StaticHostTargetProvider(TargetProvider):
    name = "static_host"

    def prepare(self, manifest: Manifest, context: RunContext, recorder: RunRecorder) -> None:
        recorder.event("target_prepared", {"provider": self.name})

    def start(self, manifest: Manifest, context: RunContext, recorder: RunRecorder) -> TargetHandle:
        target = manifest.raw.get("target", {})
        return TargetHandle(provider=self.name, target_id=manifest.id, endpoint=target.get("host"), metadata=target)

    def healthcheck(self, handle: TargetHandle, manifest: Manifest, recorder: RunRecorder) -> HealthStatus:
        checks = manifest.raw.get("target", {}).get("health", [])
        return HealthStatus(ready=bool(handle.endpoint), checks=checks)

    def collect_logs(self, handle: TargetHandle, manifest: Manifest, recorder: RunRecorder) -> None:
        recorder.event("target_logs_collected", {"provider": self.name, "status": "not_available"})

    def stop(self, handle: TargetHandle, manifest: Manifest, recorder: RunRecorder) -> None:
        recorder.event("teardown_completed", {"provider": self.name})

