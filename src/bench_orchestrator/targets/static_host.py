from __future__ import annotations

from bench_orchestrator.evidence import RunRecorder
from bench_orchestrator.models import HealthStatus, Manifest, RunContext, TargetHandle
from bench_orchestrator.targets.base import TargetProvider


class StaticHostTargetProvider(TargetProvider):
    """Provider for challenges that need no live target infrastructure.

    Covers two cases:
    - A pre-existing host (e.g. a server already running) where ``target.host``
      is set in the manifest.
    - File-based challenges (crypto, reversing, forensics) where there is no
      host at all — just files the agent needs to analyse.  The manifest's
      ``source_dir`` or ``target.challenge_dir`` points at the extracted
      challenge files.
    """

    name = "static_host"

    def prepare(self, manifest: Manifest, context: RunContext, recorder: RunRecorder) -> None:
        recorder.event("target_prepared", {"provider": self.name})

    def start(self, manifest: Manifest, context: RunContext, recorder: RunRecorder) -> TargetHandle:
        target = manifest.raw.get("target", {})
        endpoint = target.get("host")
        metadata = dict(target)
        if manifest.source_dir:
            metadata["challenge_dir"] = str(manifest.source_dir)
        recorder.event("target_started", {"provider": self.name, "endpoint": endpoint})
        return TargetHandle(
            provider=self.name,
            target_id=manifest.id,
            endpoint=endpoint,
            metadata=metadata,
        )

    def healthcheck(self, handle: TargetHandle, manifest: Manifest, recorder: RunRecorder) -> HealthStatus:
        # File-based challenges have no endpoint — always ready.
        if not handle.endpoint:
            recorder.event("target_healthy", {"static": True})
            return HealthStatus(ready=True, message="file-based challenge — no target to check")
        checks = manifest.raw.get("target", {}).get("health", [])
        if not checks:
            recorder.event("target_healthy", {"checks": []})
            return HealthStatus(ready=True)
        # If explicit health checks are configured, run them.
        from bench_orchestrator.targets.vulhub import _run_health_check
        import time
        timeout = manifest.raw.get("target", {}).get("startup_timeout_seconds", 60)
        deadline = time.monotonic() + timeout
        last_error: str | None = None
        while time.monotonic() < deadline:
            all_ok = True
            for check in checks:
                ok, err = _run_health_check(check)
                if not ok:
                    all_ok, last_error = False, err
                    break
            if all_ok:
                recorder.event("target_healthy", {"checks": checks})
                return HealthStatus(ready=True, checks=checks)
            time.sleep(5)
        recorder.event("target_unhealthy", {"checks": checks, "last_error": last_error})
        return HealthStatus(ready=False, checks=checks, message=f"Target not healthy after {timeout}s: {last_error}")

    def collect_logs(self, handle: TargetHandle, manifest: Manifest, recorder: RunRecorder) -> None:
        recorder.event("target_logs_collected", {"provider": self.name, "status": "not_available"})

    def stop(self, handle: TargetHandle, manifest: Manifest, recorder: RunRecorder) -> None:
        recorder.event("teardown_completed", {"provider": self.name})
