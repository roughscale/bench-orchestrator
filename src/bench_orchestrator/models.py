from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
import re

import yaml


RunPhase = Literal[
    "created",
    "target_prepared",
    "target_started",
    "target_healthy",
    "agent_started",
    "agent_completed",
    "scoring_completed",
    "teardown_completed",
    "failed",
]


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _safe_dirname(name: str) -> str:
    """Sanitise a name for use as a directory component."""
    return re.sub(r"[^\w.\-]", "_", name)


def new_run_id(prefix: str = "run") -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%SZ")
    return f"{prefix}_{stamp}"


@dataclass(frozen=True)
class RunContext:
    run_id: str
    root_dir: Path
    log_dir: Path
    dry_run: bool = False
    target_network: str | None = None

    @classmethod
    def create(
        cls,
        root_dir: Path,
        run_id: str | None = None,
        dry_run: bool = False,
        adapter_name: str | None = None,
        model_name: str | None = None,
        target_network: str | None = None,
    ) -> "RunContext":
        resolved_run_id = run_id or new_run_id()
        resolved_root = root_dir.resolve()
        # logs/<adapter>/<model>/<run_id>/
        log_parts: list[str] = ["logs"]
        if adapter_name:
            log_parts.append(_safe_dirname(adapter_name))
        if model_name:
            log_parts.append(_safe_dirname(model_name))
        log_parts.append(resolved_run_id)
        log_dir = resolved_root.joinpath(*log_parts)
        return cls(
            run_id=resolved_run_id,
            root_dir=resolved_root,
            log_dir=log_dir,
            dry_run=dry_run,
            target_network=target_network,
        )


@dataclass(frozen=True)
class HealthStatus:
    ready: bool
    checks: list[dict[str, Any]] = field(default_factory=list)
    message: str | None = None


@dataclass(frozen=True)
class TargetHandle:
    provider: str
    target_id: str
    network_name: str | None = None
    target_alias: str | None = None
    endpoint: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AgentResult:
    status: Literal["completed", "failed", "timed_out", "needs_input"]
    summary: str
    artifacts: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScoreResult:
    passed: bool
    scorer: str
    evidence: dict[str, Any] = field(default_factory=dict)
    message: str | None = None


@dataclass(frozen=True)
class Manifest:
    raw: dict[str, Any]
    path: Path | None = None

    @property
    def id(self) -> str:
        return str(self.raw["id"])

    @property
    def provider(self) -> str:
        return str(self.raw["provider"])

    @property
    def source_dir(self) -> Path | None:
        value = self.raw.get("source_dir")
        if not value:
            return None
        return Path(str(value))


def load_manifest(path: Path) -> Manifest:
    with path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"manifest must be a mapping: {path}")
    for key in ("id", "provider"):
        if key not in raw:
            raise ValueError(f"manifest missing required key {key!r}: {path}")
    return Manifest(raw=raw, path=path)


def dump_manifest(manifest: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(manifest, handle, sort_keys=False)

