from pathlib import Path

from bench_orchestrator.evidence import RunRecorder
from bench_orchestrator.models import RunContext, ScoreResult


def test_recorder_writes_run_files(tmp_path: Path) -> None:
    context = RunContext.create(tmp_path, run_id="test_run", dry_run=True)
    recorder = RunRecorder(context)

    recorder.initialize({"manifest": {"id": "example"}})
    recorder.command("id", return_code=0, stdout="uid=0")
    recorder.transcript("assistant", "done")
    recorder.score([ScoreResult(True, "manual", {"ok": True})])

    assert (tmp_path / "logs" / "test_run" / "metadata.json").exists()
    assert (tmp_path / "logs" / "test_run" / "events.jsonl").exists()
    assert (tmp_path / "logs" / "test_run" / "commands.jsonl").exists()
    assert (tmp_path / "logs" / "test_run" / "transcript.jsonl").exists()
    assert (tmp_path / "logs" / "test_run" / "score.json").exists()

