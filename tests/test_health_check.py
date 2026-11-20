"""_run_health_check (vulhub.py, shared by nyuctf.py; autopenbench.py has
its own duplicate for tcp/container_running): tcp/http checks run from
inside a throwaway busybox container attached to the bench run network,
not from the orchestrator's own host process.

Regression for a real failure: NyuCtfDataset sets a tcp check's "host" to
the challenge's own custom box alias (e.g. "pwn.chal.csaw.io" for
2023q-pwn-my_first_pwnie) rather than the literal string "target" - that
alias only resolves inside the Docker network the target container joins,
never from the orchestrator's own host-level process. Checked live against
NYU CTF's test-set compose files: some targets (e.g. 2023q-web-smug_dino)
publish no port to the host at all, relying purely on the network alias -
so even swapping in "127.0.0.1" wouldn't help; the only thing that works
for every case is probing from a container already on that network.
"""
from typing import Any

import bench_orchestrator.targets.autopenbench as autopenbench
import bench_orchestrator.targets.vulhub as vulhub


class _FakeCompletedProcess:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_probe_tcp_builds_busybox_nc_command_on_the_target_network(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _FakeCompletedProcess(returncode=0)

    monkeypatch.setattr(vulhub.subprocess, "run", fake_run)

    ok, err = vulhub._probe_tcp("bench_run_test", "pwn.chal.csaw.io", 31137)

    assert ok, err
    assert captured["cmd"] == [
        "docker", "run", "--rm", "--network", "bench_run_test",
        "busybox:latest", "nc", "-z", "-w", "5", "pwn.chal.csaw.io", "31137",
    ]


def test_probe_tcp_omits_network_flag_when_network_is_none(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _FakeCompletedProcess(returncode=0)

    monkeypatch.setattr(vulhub.subprocess, "run", fake_run)

    vulhub._probe_tcp(None, "target", 8080)

    assert "--network" not in captured["cmd"]


def test_probe_tcp_reports_failure_on_nonzero_exit(monkeypatch) -> None:
    monkeypatch.setattr(
        vulhub.subprocess, "run",
        lambda cmd, **k: _FakeCompletedProcess(returncode=1, stderr="nc: connect: Connection refused"),
    )

    ok, err = vulhub._probe_tcp("net", "target", 8080)

    assert not ok
    assert "Connection refused" in err


def test_probe_http_parses_status_code_from_busybox_wget_output(monkeypatch) -> None:
    # Real output captured live from `docker run --rm busybox wget -S --spider ...`
    wget_output = (
        "Connecting to pwn.chal.csaw.io (10.0.0.5:80)\n"
        "  HTTP/1.1 200 OK\n"
        "  Date: Fri, 20 Nov 2026 00:55:16 GMT\n"
    )
    monkeypatch.setattr(
        vulhub.subprocess, "run",
        lambda cmd, **k: _FakeCompletedProcess(returncode=0, stdout=wget_output),
    )

    ok, err = vulhub._probe_http("bench_run_test", "http://pwn.chal.csaw.io/", [200, 302, 401, 403])

    assert ok, err


def test_probe_http_accepts_403_as_healthy_despite_nonzero_wget_exit(monkeypatch) -> None:
    # busybox wget exits non-zero for any non-2xx response (confirmed live)
    # - the status code must be parsed from the text, not inferred from the
    # exit code, since 401/403/302 are explicitly "healthy" by convention.
    wget_output = "Connecting to target (10.0.0.5:80)\n  HTTP/1.1 403 Forbidden\nwget: server returned error\n"
    monkeypatch.setattr(
        vulhub.subprocess, "run",
        lambda cmd, **k: _FakeCompletedProcess(returncode=1, stdout="", stderr=wget_output),
    )

    ok, err = vulhub._probe_http("net", "http://target/", [200, 302, 401, 403])

    assert ok, err


def test_probe_http_rejects_status_not_in_expect_list(monkeypatch) -> None:
    wget_output = "  HTTP/1.1 500 Internal Server Error\n"
    monkeypatch.setattr(
        vulhub.subprocess, "run",
        lambda cmd, **k: _FakeCompletedProcess(returncode=1, stderr=wget_output),
    )

    ok, err = vulhub._probe_http("net", "http://target/", [200, 302, 401, 403])

    assert not ok
    assert "500" in err


def test_probe_http_reports_no_response_when_connection_refused(monkeypatch) -> None:
    # No HTTP/x.x status line at all - e.g. connection refused.
    wget_output = "Connecting to 127.0.0.1:19999 (127.0.0.1:19999)\nwget: can't connect to remote host: Connection refused\n"
    monkeypatch.setattr(
        vulhub.subprocess, "run",
        lambda cmd, **k: _FakeCompletedProcess(returncode=1, stderr=wget_output),
    )

    ok, err = vulhub._probe_http("net", "http://target/", [200])

    assert not ok
    assert "no HTTP response" in err


def test_probe_http_builds_busybox_wget_command(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _FakeCompletedProcess(returncode=0, stdout="HTTP/1.1 200 OK\n")

    monkeypatch.setattr(vulhub.subprocess, "run", fake_run)

    vulhub._probe_http("bench_run_test", "http://target:8080/", [200])

    assert captured["cmd"] == [
        "docker", "run", "--rm", "--network", "bench_run_test",
        "busybox:latest", "wget", "-S", "--spider", "-T", "5", "http://target:8080/",
    ]


def test_run_health_check_dispatches_tcp_with_network(monkeypatch) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(vulhub, "_probe_tcp", lambda network, host, port: captured.update(network=network, host=host, port=port) or (True, None))

    ok, err = vulhub._run_health_check({"type": "tcp", "host": "pwn.chal.csaw.io", "port": 31137}, network="bench_run_test")

    assert ok, err
    assert captured == {"network": "bench_run_test", "host": "pwn.chal.csaw.io", "port": 31137}


def test_run_health_check_dispatches_http_with_network(monkeypatch) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        vulhub, "_probe_http",
        lambda network, url, expect: captured.update(network=network, url=url, expect=expect) or (True, None),
    )

    ok, err = vulhub._run_health_check({"type": "http", "url": "http://target/"}, network="bench_run_test")

    assert ok, err
    assert captured == {"network": "bench_run_test", "url": "http://target/", "expect": [200, 302, 401, 403]}


def test_autopenbench_tcp_check_reuses_vulhub_probe_tcp(monkeypatch) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        autopenbench, "_probe_tcp",
        lambda network, host, port: captured.update(network=network, host=host, port=port) or (True, None),
    )

    ok, err = autopenbench._run_health_check({"type": "tcp", "host": "some-custom-alias", "port": 22}, network="autopenbench_net")

    assert ok, err
    assert captured == {"network": "autopenbench_net", "host": "some-custom-alias", "port": 22}


def test_autopenbench_container_running_check_unaffected(monkeypatch) -> None:
    # container_running checks docker inspect directly and never needs the
    # network at all - must keep working unchanged.
    monkeypatch.setattr(
        autopenbench.subprocess, "run",
        lambda cmd, **k: _FakeCompletedProcess(returncode=0, stdout="running\n"),
    )

    ok, err = autopenbench._run_health_check({"type": "container_running", "container": "vm0"}, network="autopenbench_net")

    assert ok, err
