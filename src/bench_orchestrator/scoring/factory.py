from __future__ import annotations

from typing import Any

from bench_orchestrator.scoring.base import Scorer
from bench_orchestrator.scoring.command_check import CommandCheckScorer
from bench_orchestrator.scoring.flag import FlagScorer
from bench_orchestrator.scoring.flag_pattern import FlagPatternScorer
from bench_orchestrator.scoring.http_probe import HttpProbeScorer
from bench_orchestrator.scoring.stage_milestones import StageMilestoneScorer


def build_scorer(config: dict[str, Any]) -> Scorer | None:
    scorer_type = config.get("type")
    if scorer_type == "needs_curation":
        return None
    if scorer_type == "http_probe":
        return HttpProbeScorer(str(config["url"]), expect_status=config.get("expect_status"))
    if scorer_type == "command_check":
        return CommandCheckScorer(str(config["command"]))
    if scorer_type == "flag":
        return FlagScorer(str(config["value"]))
    if scorer_type == "flag_pattern":
        return FlagPatternScorer(str(config["pattern"]))
    if scorer_type == "stage_milestones":
        return StageMilestoneScorer(list(config.get("required", [])))
    raise ValueError(f"unknown scorer type: {scorer_type}")


def build_scorers(configs: list[dict[str, Any]]) -> list[Scorer]:
    scorers: list[Scorer] = []
    for config in configs:
        scorer = build_scorer(config)
        if scorer is not None:
            scorers.append(scorer)
    return scorers

