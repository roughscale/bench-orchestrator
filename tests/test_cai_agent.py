"""CaiAgentAdapter docker-command construction and lifecycle."""
import subprocess

import bench_orchestrator.agents.cai_agent as cai_agent
from bench_orchestrator.agents.cai_agent import CaiAgentAdapter, _build_docker_cmd, _build_env, _docker_run, _flag_pattern
from bench_orchestrator.evidence import RunRecorder
from bench_orchestrator.models import Manifest, RunContext, TargetHandle


def _manifest(task: str = "Find the flag.") -> Manifest:
    return Manifest(raw={"id": "htb/challenges/x", "provider": "static_host", "task": task})


def test_flag_pattern_read_regardless_of_scorer_type() -> None:
    # verified_flags doesn't itself use "pattern" (correctness is decided
    # live by cai's submit_flag tool) - but CHALLENGE_FLAG_PATTERN still
    # needs it, as submit_flag's own local-verification fallback. Must not
    # be gated on type == "flag_pattern", or this silently stops being set.
    manifest = Manifest(raw={
        "id": "htb/challenges/x", "provider": "static_host", "task": "x",
        "goal": {"success": [{"type": "verified_flags", "pattern": r"HTB\{[^}]+\}"}]},
    })

    assert _flag_pattern(manifest) == r"HTB\{[^}]+\}"


def test_build_env_uses_target_for_live_targets() -> None:
    env = _build_env(_manifest(), target_desc="10.129.1.5", agent_config={}, api_keys={})

    assert "Target: 10.129.1.5" in env["CHALLENGE_PROMPT"]
    assert env["TARGET_HOST"] == "10.129.1.5"


def test_build_env_mentions_challenge_mount_for_file_based_challenges() -> None:
    # StaticHostTargetProvider challenges have no target_desc at all - the
    # prompt must point at the mounted files instead of an empty "Target: ".
    env = _build_env(_manifest(), target_desc="", agent_config={}, api_keys={}, challenge_mount="/opt/cai/challenge")

    assert "Target:" not in env["CHALLENGE_PROMPT"]
    assert "/opt/cai/challenge" in env["CHALLENGE_PROMPT"]
    assert "TARGET_HOST" not in env


def test_build_env_sets_flags_required() -> None:
    env = _build_env(_manifest(), target_desc="10.129.1.5", agent_config={}, api_keys={}, flags_required=2)

    assert env["CHALLENGE_FLAGS_REQUIRED"] == "2"


def test_build_env_defaults_flags_required_to_one() -> None:
    env = _build_env(_manifest(), target_desc="10.129.1.5", agent_config={}, api_keys={})

    assert env["CHALLENGE_FLAGS_REQUIRED"] == "1"


def test_docker_cmd_adds_host_gateway_for_verify_server_reachability() -> None:
    # Needed regardless of --network mode - see htb_flag_verify_server.py -
    # so the container can reach a verification server bound on the host
    # even on the default bridge network, where 127.0.0.1 is the container
    # itself, not the host.
    cmd = _build_docker_cmd("cai-bench:latest", env={}, network=None, volumes={}, container_name="cai-bench-test")

    assert "--add-host=host.docker.internal:host-gateway" in cmd


def test_docker_cmd_grants_net_caps_for_nmap() -> None:
    # nmap in the image has cap_net_admin/cap_net_raw file caps; without both
    # in the container's bounding set the kernel refuses to exec it at all.
    cmd = _build_docker_cmd("cai-bench:latest", env={}, network=None, volumes={}, container_name="cai-bench-test")

    assert "--cap-add=NET_ADMIN" in cmd
    assert "--cap-add=NET_RAW" in cmd


def test_docker_cmd_shape() -> None:
    cmd = _build_docker_cmd(
        "cai-bench:latest",
        env={"CHALLENGE_PROMPT": "go", "CAI_MODEL": "claude-sonnet-5"},
        network="host",
        volumes={"/host/x": "/container/x"},
        container_name="cai-bench-test",
    )

    assert cmd[:3] == ["docker", "run", "--rm"]
    assert "--name" in cmd and "cai-bench-test" in cmd
    assert "--network=host" in cmd
    assert cmd[-1] == "cai-bench:latest"  # image is last
    # env pairs present
    joined = " ".join(cmd)
    assert "-e CHALLENGE_PROMPT=go" in joined
    assert "-e CAI_MODEL=claude-sonnet-5" in joined
    assert "-v /host/x:/container/x" in joined


def test_docker_run_timeout_kills_named_container(monkeypatch) -> None:
    """Regression: proc.kill() on TimeoutExpired only kills the local `docker
    run` client, not the container itself (Docker doesn't stop the daemon
    side just because the client died) - observed live as containers still
    running hours after their task was reported as timed out. _docker_run
    must `docker kill <container_name>` too."""

    class FakeProc:
        stdout = iter([])
        stderr = iter([])

        def wait(self, timeout):
            raise subprocess.TimeoutExpired(cmd="docker run", timeout=timeout)

        def kill(self):
            pass

    monkeypatch.setattr(cai_agent.subprocess, "Popen", lambda *a, **k: FakeProc())

    killed = []
    monkeypatch.setattr(
        cai_agent.subprocess,
        "run",
        lambda cmd, **k: killed.append(cmd),
    )

    result, error, stdout, stderr = _docker_run(["docker", "run", "..."], timeout_s=1, container_name="cai-bench-abc123")

    assert error == "wall-clock timeout after 1s"
    assert killed == [["docker", "kill", "cai-bench-abc123"]]


def test_docker_run_kills_container_on_unexpected_exception(monkeypatch) -> None:
    """Any other exception unwinding _docker_run (e.g. KeyboardInterrupt) must
    still reach for the named container - not just the timeout path."""

    class FakeProc:
        stdout = iter([])
        stderr = iter([])

        def wait(self, timeout):
            raise KeyboardInterrupt()

        def kill(self):
            pass

    monkeypatch.setattr(cai_agent.subprocess, "Popen", lambda *a, **k: FakeProc())

    killed = []
    monkeypatch.setattr(
        cai_agent.subprocess,
        "run",
        lambda cmd, **k: killed.append(cmd),
    )

    try:
        _docker_run(["docker", "run", "..."], timeout_s=1, container_name="cai-bench-def456")
        raised = False
    except KeyboardInterrupt:
        raised = True

    assert raised, "KeyboardInterrupt should propagate, not be swallowed"
    assert killed == [["docker", "kill", "cai-bench-def456"]]


def test_run_mounts_challenge_dir_for_file_based_challenges(tmp_path, monkeypatch) -> None:
    """StaticHostTargetProvider sets target.metadata["challenge_dir"] for
    file-based challenges (no live host) - CaiAgentAdapter must mount it into
    the container, or the agent has nothing to analyse regardless of whether
    the files were downloaded."""
    challenge_files = tmp_path / "downloaded" / "spookifier"
    challenge_files.mkdir(parents=True)
    (challenge_files / "app.py").write_text("# challenge source")

    captured_volumes = {}

    def fake_build_docker_cmd(*, image, env, network, volumes, container_name):
        captured_volumes.update(volumes)
        return ["docker", "run", "--rm", image]

    def fake_docker_run(cmd, timeout_s, container_name):
        return {"solved": False}, None, "", ""

    monkeypatch.setattr(cai_agent, "_build_docker_cmd", fake_build_docker_cmd)
    monkeypatch.setattr(cai_agent, "_docker_run", fake_docker_run)

    adapter = CaiAgentAdapter(image="cai-bench:latest")
    manifest = Manifest(raw={"id": "htb/challenges/spookifier", "provider": "static_host", "task": "Find the flag."})
    target = TargetHandle(
        provider="static_host",
        target_id="htb/challenges/spookifier",
        metadata={"challenge_dir": str(challenge_files)},
    )
    context = RunContext.create(tmp_path, run_id="run_test")
    recorder = RunRecorder(context)
    recorder.initialize({"manifest": manifest.raw})

    adapter.run(manifest, target, context, recorder)

    assert captured_volumes.get(str(challenge_files.resolve())) == "/opt/cai/challenge"


def test_run_starts_and_stops_verify_server_and_passes_its_url(tmp_path, monkeypatch) -> None:
    events = []

    class FakeServer:
        port = 54321

        def start(self):
            events.append("started")

        def stop(self):
            events.append("stopped")

    captured_env = {}

    def fake_build_docker_cmd(*, image, env, network, volumes, container_name):
        captured_env.update(env)
        return ["docker", "run", "--rm", image]

    def fake_docker_run(cmd, timeout_s, container_name):
        assert events == ["started"]  # must be running before the container starts
        return {"solved": False, "flags": []}, None, "", ""

    monkeypatch.setenv("HTB_API_KEY", "key")
    monkeypatch.setattr(cai_agent, "build_verify_server", lambda manifest, target, api_key: FakeServer())
    monkeypatch.setattr(cai_agent, "_build_docker_cmd", fake_build_docker_cmd)
    monkeypatch.setattr(cai_agent, "_docker_run", fake_docker_run)

    adapter = CaiAgentAdapter(image="cai-bench:latest")
    manifest = Manifest(raw={"id": "htb/challenges/diagnostic", "provider": "htb_challenge", "task": "Find the flag."})
    target = TargetHandle(provider="htb_challenge", target_id="htb/challenges/diagnostic", metadata={"challenge_id": 360})
    context = RunContext.create(tmp_path, run_id="run_test")
    recorder = RunRecorder(context)
    recorder.initialize({"manifest": manifest.raw})

    adapter.run(manifest, target, context, recorder)

    assert events == ["started", "stopped"]
    assert captured_env["CHALLENGE_FLAG_VERIFY_URL"] == "http://host.docker.internal:54321/verify"


def test_run_skips_verify_server_when_htb_api_key_unset(tmp_path, monkeypatch) -> None:
    called = []
    captured_env = {}

    def fake_build_docker_cmd(*, image, env, network, volumes, container_name):
        captured_env.update(env)
        return ["docker", "run", "--rm", image]

    monkeypatch.delenv("HTB_API_KEY", raising=False)
    monkeypatch.setattr(cai_agent, "build_verify_server", lambda *a, **k: called.append(1))
    monkeypatch.setattr(cai_agent, "_build_docker_cmd", fake_build_docker_cmd)
    monkeypatch.setattr(cai_agent, "_docker_run", lambda cmd, timeout_s, container_name: ({"solved": False, "flags": []}, None, "", ""))

    adapter = CaiAgentAdapter(image="cai-bench:latest")
    manifest = Manifest(raw={"id": "htb/challenges/spookifier", "provider": "static_host", "task": "Find the flag."})
    target = TargetHandle(provider="static_host", target_id="htb/challenges/spookifier")
    context = RunContext.create(tmp_path, run_id="run_test")
    recorder = RunRecorder(context)
    recorder.initialize({"manifest": manifest.raw})

    adapter.run(manifest, target, context, recorder)

    assert called == []  # never even attempted without an API key
    assert "CHALLENGE_FLAG_VERIFY_URL" not in captured_env
