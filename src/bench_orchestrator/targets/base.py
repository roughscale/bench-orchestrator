from __future__ import annotations

from abc import ABC, abstractmethod

from bench_orchestrator.evidence import RunRecorder
from bench_orchestrator.models import HealthStatus, Manifest, RunContext, TargetHandle


class TargetProvider(ABC):
    name: str

    @abstractmethod
    def prepare(self, manifest: Manifest, context: RunContext, recorder: RunRecorder) -> None:
        raise NotImplementedError

    @abstractmethod
    def start(self, manifest: Manifest, context: RunContext, recorder: RunRecorder) -> TargetHandle:
        raise NotImplementedError

    @abstractmethod
    def healthcheck(self, handle: TargetHandle, manifest: Manifest, recorder: RunRecorder) -> HealthStatus:
        raise NotImplementedError

    @abstractmethod
    def collect_logs(self, handle: TargetHandle, manifest: Manifest, recorder: RunRecorder) -> None:
        raise NotImplementedError

    @abstractmethod
    def stop(self, handle: TargetHandle, manifest: Manifest, recorder: RunRecorder) -> None:
        raise NotImplementedError

