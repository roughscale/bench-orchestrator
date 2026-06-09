from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bench_orchestrator.models import RunContext, ScoreResult, utc_now


class RunRecorder:
    """Append-only evidence recorder for one benchmark run."""

    def __init__(self, context: RunContext):
        self.context = context
        self.log_dir = context.log_dir
        self.artifact_dir = self.log_dir / "artifacts"
        self.target_log_dir = self.log_dir / "target_logs"

    def initialize(self, metadata: dict[str, Any]) -> None:
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.target_log_dir.mkdir(parents=True, exist_ok=True)
        self.write_json("metadata.json", {"run_id": self.context.run_id, "created_at": utc_now(), **metadata})
        self.event("created", {"dry_run": self.context.dry_run})

    def event(self, phase: str, payload: dict[str, Any] | None = None) -> None:
        self.append_jsonl("events.jsonl", {"ts": utc_now(), "phase": phase, "payload": payload or {}})

    def command(
        self,
        command: str,
        *,
        cwd: str | None = None,
        return_code: int | None = None,
        stdout: str | None = None,
        stderr: str | None = None,
        timeout_seconds: int | None = None,
        container: str | None = None,
    ) -> None:
        self.append_jsonl(
            "commands.jsonl",
            {
                "ts": utc_now(),
                "command": command,
                "cwd": cwd,
                "return_code": return_code,
                "stdout": stdout,
                "stderr": stderr,
                "timeout_seconds": timeout_seconds,
                "container": container,
            },
        )

    def transcript(self, role: str, content: str, metadata: dict[str, Any] | None = None) -> None:
        self.append_jsonl(
            "transcript.jsonl",
            {"ts": utc_now(), "role": role, "content": content, "metadata": metadata or {}},
        )

    def score(self, results: list[ScoreResult]) -> None:
        self.write_json(
            "score.json",
            {
                "ts": utc_now(),
                "passed": all(result.passed for result in results),
                "results": [
                    {
                        "passed": result.passed,
                        "scorer": result.scorer,
                        "message": result.message,
                        "evidence": result.evidence,
                    }
                    for result in results
                ],
            },
        )
        self.event("scoring_completed")

    def write_json(self, relative_path: str, payload: dict[str, Any]) -> Path:
        path = self.log_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def append_jsonl(self, relative_path: str, payload: dict[str, Any]) -> Path:
        path = self.log_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
        return path

    def artifact_path(self, name: str) -> Path:
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        return self.artifact_dir / name

