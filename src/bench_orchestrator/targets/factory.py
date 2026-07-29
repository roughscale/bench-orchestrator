from __future__ import annotations

from bench_orchestrator.targets.autopenbench import AutoPenBenchTargetProvider
from bench_orchestrator.targets.base import TargetProvider
from bench_orchestrator.targets.htb import HtbTargetProvider
from bench_orchestrator.targets.static_host import StaticHostTargetProvider
from bench_orchestrator.targets.vulhub import VulhubTargetProvider


def build_target_provider(name: str) -> TargetProvider:
    if name == "autopenbench":
        return AutoPenBenchTargetProvider()
    if name == "vulhub":
        return VulhubTargetProvider()
    if name == "htb":
        return HtbTargetProvider()
    if name == "static_host":
        return StaticHostTargetProvider()
    raise ValueError(f"unknown target provider: {name}")
