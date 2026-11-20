"""EnigmaAgentAdapter docker-command construction and lifecycle."""
import subprocess

import pytest

import bench_orchestrator.agents.enigma as enigma
from bench_orchestrator.agents.enigma import EnigmaAgentAdapter, _build_docker_cmd, _docker_run
from bench_orchestrator.agents.factory import build_agent_adapter
from bench_orchestrator.evidence import RunRecorder
from bench_orchestrator.models import Manifest, RunContext, TargetHandle


def _manifest(source_dir) -> Manifest:
    return Manifest(raw={"id": "nyuctf/2018f-msc-leaked_flag", "provider": "nyuctf", "source_dir": str(source_dir)})


def _challenge_dir(tmp_path):
    challenge_dir = tmp_path / "challenge"
    challenge_dir.mkdir()
    (challenge_dir / "challenge.json").write_text("{}")
    return challenge_dir


def test_factory_builds_enigma_adapter_with_default_image() -> None:
    adapter = build_agent_adapter("enigma", agent_config={"model": "claude-sonnet-5"})

    assert isinstance(adapter, EnigmaAgentAdapter)
    assert adapter.image == "enigma-bench:latest"


def test_factory_builds_enigma_adapter_with_image_override() -> None:
    adapter = build_agent_adapter("enigma", image="ghcr.io/roughscale/enigma:test")

    assert isinstance(adapter, EnigmaAgentAdapter)
    assert adapter.image == "ghcr.io/roughscale/enigma:test"


def test_model_name_reads_from_agent_config() -> None:
    adapter = EnigmaAgentAdapter(agent_config={"model": "claude-sonnet-5"})

    assert adapter.model_name == "claude-sonnet-5"


def test_docker_cmd_mounts_socket_and_challenge_dir() -> None:
    cmd = _build_docker_cmd(
        "enigma-bench:latest",
        env={"MODEL_NAME": "claude-sonnet-5"},
        volumes={"/host/challenge": "/opt/enigma/challenge:ro"},
        container_name="enigma-bench-test",
    )

    assert cmd[:3] == ["docker", "run", "--rm"]
    assert "--name" in cmd and "enigma-bench-test" in cmd
    joined = " ".join(cmd)
    assert "-v /var/run/docker.sock:/var/run/docker.sock" in joined
    assert "-v /host/challenge:/opt/enigma/challenge:ro" in joined
    assert "-e MODEL_NAME=claude-sonnet-5" in joined
    # No --network flag at all - EnIGMA's exec container addresses the target
    # via ctfnet, not bench-orchestrator's per-run network.
    assert not any(part.startswith("--network=") for part in cmd)
    # bench/runner.py is invoked explicitly rather than relying on an
    # ENTRYPOINT baked into the image.
    assert cmd[-2:] == ["python", "bench/runner.py"]


def test_prepare_requires_challenge_json(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "key")
    empty_dir = tmp_path / "no_challenge_json"
    empty_dir.mkdir()
    adapter = EnigmaAgentAdapter()
    manifest = _manifest(empty_dir)
    context = RunContext.create(tmp_path, run_id="run_test")
    recorder = RunRecorder(context)
    recorder.initialize({"manifest": manifest.raw})

    with pytest.raises(FileNotFoundError):
        adapter.prepare(manifest, TargetHandle(provider="nyuctf", target_id=manifest.id), context, recorder)


def test_prepare_requires_an_api_key(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    challenge_dir = _challenge_dir(tmp_path)
    adapter = EnigmaAgentAdapter()
    manifest = _manifest(challenge_dir)
    context = RunContext.create(tmp_path, run_id="run_test")
    recorder = RunRecorder(context)
    recorder.initialize({"manifest": manifest.raw})

    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        adapter.prepare(manifest, TargetHandle(provider="nyuctf", target_id=manifest.id), context, recorder)


def test_run_mounts_source_dir_and_parses_solved_result(tmp_path, monkeypatch) -> None:
    challenge_dir = _challenge_dir(tmp_path)
    captured = {}

    def fake_build_docker_cmd(*, image, env, volumes, container_name):
        captured["env"] = env
        captured["volumes"] = volumes
        return ["docker", "run", "--rm", image]

    def fake_docker_run(cmd, timeout_s, container_name):
        return {"solved": True, "submission": "flag{abc}", "exit_status": "submitted"}, None, "", ""

    monkeypatch.setattr(enigma, "_build_docker_cmd", fake_build_docker_cmd)
    monkeypatch.setattr(enigma, "_docker_run", fake_docker_run)

    adapter = EnigmaAgentAdapter(agent_config={"model": "claude-sonnet-5"})
    manifest = _manifest(challenge_dir)
    context = RunContext.create(tmp_path, run_id="run_test")
    recorder = RunRecorder(context)
    recorder.initialize({"manifest": manifest.raw})

    result = adapter.run(manifest, TargetHandle(provider="nyuctf", target_id=manifest.id), context, recorder)

    assert captured["volumes"] == {str(challenge_dir.resolve()): "/opt/enigma/challenge:ro"}
    assert captured["env"]["MODEL_NAME"] == "claude-sonnet-5"
    assert captured["env"]["CHALLENGE_DIR"] == "/opt/enigma/challenge"
    assert result.status == "completed"
    assert "flag{abc}" in result.summary


def test_run_reports_failed_when_not_solved(tmp_path, monkeypatch) -> None:
    challenge_dir = _challenge_dir(tmp_path)

    monkeypatch.setattr(enigma, "_build_docker_cmd", lambda **k: ["docker", "run", "--rm", "x"])
    monkeypatch.setattr(
        enigma, "_docker_run",
        lambda cmd, timeout_s, container_name: ({"solved": False, "submission": None, "exit_status": "exit_forfeit"}, None, "", ""),
    )

    adapter = EnigmaAgentAdapter(agent_config={"model": "claude-sonnet-5"})
    manifest = _manifest(challenge_dir)
    context = RunContext.create(tmp_path, run_id="run_test")
    recorder = RunRecorder(context)
    recorder.initialize({"manifest": manifest.raw})

    result = adapter.run(manifest, TargetHandle(provider="nyuctf", target_id=manifest.id), context, recorder)

    assert result.status == "failed"


def test_run_reports_failed_on_docker_error(tmp_path, monkeypatch) -> None:
    challenge_dir = _challenge_dir(tmp_path)

    monkeypatch.setattr(enigma, "_build_docker_cmd", lambda **k: ["docker", "run", "--rm", "x"])
    monkeypatch.setattr(enigma, "_docker_run", lambda cmd, timeout_s, container_name: ({}, "no output from runner", "", ""))

    adapter = EnigmaAgentAdapter(agent_config={"model": "claude-sonnet-5"})
    manifest = _manifest(challenge_dir)
    context = RunContext.create(tmp_path, run_id="run_test")
    recorder = RunRecorder(context)
    recorder.initialize({"manifest": manifest.raw})

    result = adapter.run(manifest, TargetHandle(provider="nyuctf", target_id=manifest.id), context, recorder)

    assert result.status == "failed"
    assert "no output from runner" in result.summary


def test_run_reports_timed_out_on_timeout(tmp_path, monkeypatch) -> None:
    challenge_dir = _challenge_dir(tmp_path)

    monkeypatch.setattr(enigma, "_build_docker_cmd", lambda **k: ["docker", "run", "--rm", "x"])
    monkeypatch.setattr(
        enigma, "_docker_run",
        lambda cmd, timeout_s, container_name: ({}, "wall-clock timeout after 5s", "", ""),
    )

    adapter = EnigmaAgentAdapter(agent_config={"model": "claude-sonnet-5"})
    manifest = _manifest(challenge_dir)
    context = RunContext.create(tmp_path, run_id="run_test")
    recorder = RunRecorder(context)
    recorder.initialize({"manifest": manifest.raw})

    result = adapter.run(manifest, TargetHandle(provider="nyuctf", target_id=manifest.id), context, recorder)

    assert result.status == "timed_out"


def test_docker_run_timeout_kills_named_container(monkeypatch) -> None:
    """Same regression guard as test_cai_agent.py: the local `docker run`
    client dying on timeout does not stop the container's daemon side -
    _docker_run must `docker kill <container_name>` too."""

    class FakeProc:
        stdout = iter([])
        stderr = iter([])

        def wait(self, timeout):
            raise subprocess.TimeoutExpired(cmd="docker run", timeout=timeout)

        def kill(self):
            pass

    monkeypatch.setattr(enigma.subprocess, "Popen", lambda *a, **k: FakeProc())

    killed = []
    monkeypatch.setattr(enigma.subprocess, "run", lambda cmd, **k: killed.append(cmd))

    result, error, stdout, stderr = _docker_run(["docker", "run", "..."], timeout_s=1, container_name="enigma-bench-abc123")

    assert error == "wall-clock timeout after 1s"
    assert killed == [["docker", "kill", "enigma-bench-abc123"]]
