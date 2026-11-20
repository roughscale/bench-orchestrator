from __future__ import annotations

import json
import os
import subprocess
import threading
import uuid
from pathlib import Path
from typing import Any

from bench_orchestrator.agents.base import AgentAdapter
from bench_orchestrator.evidence import RunRecorder
from bench_orchestrator.models import AgentResult, Manifest, RunContext, TargetHandle

# EnIGMA's model registry (research/enigma-ctf's patched sweagent/agent/models.py)
# only exercises Anthropic and OpenAI directly for the models this project cares
# about (claude-sonnet-5, gpt-5.6-terra) - same _API_KEY_VARS-style check
# cai_agent.py uses, scoped to what EnIGMA actually needs.
_API_KEY_VARS = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY")

_DEFAULT_IMAGE = "enigma-bench:latest"

# Mount point for the read-only challenge directory inside the enigma-bench
# container. Unlike the sibling-container concerns that would apply if this
# container itself ran `docker compose` against bind-mounted paths, this one
# doesn't - bench/runner.py (research/enigma-ctf) strips any docker-compose
# file before invoking run.py, and run.py's own repo-copy step uses `docker
# cp`, which works regardless of whether this path matches anything on the
# real Docker host. So any mount point is fine here.
_CHALLENGE_MOUNT = "/opt/enigma/challenge"


class EnigmaAgentAdapter(AgentAdapter):
    """Adapter for the EnIGMA agent harness (research/enigma-ctf, a patched
    SWE-agent v0.7 checkout with its `--ctf` extensions).

    research/enigma-ctf/bench/runner.py is EnIGMA's own non-interactive bench
    entry point - same role as cai's bench/runner.py: it reads env vars, runs
    the challenge to completion via the real `run.py` CLI, and prints one JSON
    result line to stdout. So, like CaiAgentAdapter, this is a single `docker
    run --rm` per task rather than a long-lived container to exec into.

    The target itself (started by NyuCtfTargetProvider before this adapter
    runs) is not addressed via `target` at all - EnIGMA's own exec container
    reaches it over the `ctfnet` Docker network it joins unconditionally for
    any CTF-mode run, using the service-name alias already encoded in the
    challenge's own challenge.json ("box"/"internal_port"). See
    bench/runner.py's module docstring for why that's safe (no double-start
    of the target's compose project).
    """

    name = "enigma"

    def __init__(self, image: str = _DEFAULT_IMAGE, agent_config: dict[str, Any] | None = None) -> None:
        self.image = image
        self.agent_config: dict[str, Any] = agent_config or {}
        self._api_keys: dict[str, str] = {}

    @property
    def model_name(self) -> str | None:
        return self.agent_config.get("model")

    def prepare(
        self,
        manifest: Manifest,
        target: TargetHandle,
        context: RunContext,
        recorder: RunRecorder,
    ) -> None:
        if context.dry_run:
            recorder.event("agent_prepared", {"adapter": self.name, "dry_run": True})
            return

        source_dir = _require_challenge_dir(manifest)
        if not (source_dir / "challenge.json").is_file():
            raise FileNotFoundError(f"challenge.json not found in {source_dir}")

        api_keys = {k: os.environ[k] for k in _API_KEY_VARS if k in os.environ}
        if not api_keys:
            raise RuntimeError(f"enigma adapter requires at least one of {', '.join(_API_KEY_VARS)} to be set")
        self._api_keys = api_keys
        recorder.event("agent_prepared", {"adapter": self.name, "image": self.image})

    def run(
        self,
        manifest: Manifest,
        target: TargetHandle,
        context: RunContext,
        recorder: RunRecorder,
    ) -> AgentResult:
        source_dir = _require_challenge_dir(manifest)
        model = self.agent_config.get("model")
        if not model:
            raise RuntimeError("enigma adapter requires agent config key 'model'")

        env = {
            "MODEL_NAME": model,
            "PER_INSTANCE_COST_LIMIT": str(self.agent_config.get("per_instance_cost_limit", 3.0)),
            "CONFIG_FILE": self.agent_config.get("config_file", "config/default_ctf.yaml"),
            "CHALLENGE_DIR": _CHALLENGE_MOUNT,
            **self._api_keys,
        }
        if "temperature" in self.agent_config:
            env["TEMPERATURE"] = str(self.agent_config["temperature"])
        if "top_p" in self.agent_config:
            env["TOP_P"] = str(self.agent_config["top_p"])

        if context.dry_run:
            recorder.event(
                "agent_completed",
                {"adapter": self.name, "dry_run": True, "env_keys": sorted(env)},
            )
            return AgentResult(status="completed", summary="Dry-run enigma adapter execution.")

        timeout = int(self.agent_config.get("timeout_seconds", 3600))
        recorder.event("agent_started", {"adapter": self.name, "timeout_seconds": timeout})

        container_name = f"enigma-bench-{uuid.uuid4().hex[:12]}"
        cmd = _build_docker_cmd(
            image=self.image,
            env=env,
            volumes={str(source_dir.resolve()): f"{_CHALLENGE_MOUNT}:ro"},
            container_name=container_name,
        )
        result, error, stdout, stderr = _docker_run(cmd, timeout_s=timeout, container_name=container_name)

        recorder.command(
            _redact(cmd),
            return_code=0 if error is None else 1,
            stdout=stdout,
            stderr=stderr,
            timeout_seconds=timeout,
        )
        if stdout:
            recorder.transcript(role="agent", content=stdout, metadata={"adapter": self.name})

        if error is not None:
            recorder.event("agent_completed", {"adapter": self.name, "status": "failed", "error": error})
            status = "timed_out" if "timeout" in error else "failed"
            return AgentResult(status=status, summary=f"enigma run failed: {error}", metadata={"error": error})

        solved = bool(result.get("solved"))
        summary = f"EnIGMA exit_status={result.get('exit_status')!r}; submission={result.get('submission')!r}"
        recorder.event("agent_completed", {"adapter": self.name, "status": "completed" if solved else "failed", "result": result})
        return AgentResult(
            status="completed" if solved else "failed",
            summary=summary,
            metadata=result,
        )

    def stop(self, recorder: RunRecorder) -> None:
        # The container runs with --rm and has already exited by the time
        # run() returns - nothing left to tear down.
        recorder.event("agent_stopped", {"adapter": self.name})


# ------------------------------------------------------------------
# Env / command construction
# ------------------------------------------------------------------

def _require_challenge_dir(manifest: Manifest) -> Path:
    source_dir = manifest.source_dir
    if source_dir is None:
        raise ValueError(f"manifest {manifest.id} is missing source_dir")
    return source_dir


def _build_docker_cmd(
    image: str,
    env: dict[str, str],
    volumes: dict[str, str],
    container_name: str,
) -> list[str]:
    cmd = ["docker", "run", "--rm", "--name", container_name]
    # SWE-agent's own run.py spawns a sibling exec container
    # (sweagent/enigma:latest) via the Docker API for every run - the socket
    # mount lets that reach the host daemon from inside this container.
    cmd += ["-v", "/var/run/docker.sock:/var/run/docker.sock"]
    for key, value in env.items():
        cmd += ["-e", f"{key}={value}"]
    for host_path, container_path in volumes.items():
        cmd += ["-v", f"{host_path}:{container_path}"]
    cmd += [image, "python", "bench/runner.py"]
    return cmd


def _kill_container(container_name: str) -> None:
    """Best-effort `docker kill` on a named container - see cai_agent.py's
    identically-named helper for why this is needed on top of --rm."""
    try:
        subprocess.run(
            ["docker", "kill", container_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
    except Exception:
        pass


def _docker_run(cmd: list[str], timeout_s: int, container_name: str) -> tuple[dict[str, Any], str | None, str, str]:
    """Run the enigma-bench container; stream stderr, parse the trailing JSON stdout line.

    Same contract as cai_agent.py's own _docker_run - bench/runner.py can log
    progress/noise to stdout ahead of its final result, so the last line that
    parses as JSON and looks like a result (has a "solved" key) is the answer.
    """
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception as exc:
        return {}, str(exc), "", ""

    stdout_lines: list[str] = []
    stderr_lines: list[str] = []

    def collect(stream: Any, sink: list[str]) -> None:
        for line in stream:
            sink.append(line)

    stdout_thread = threading.Thread(target=collect, args=(proc.stdout, stdout_lines), daemon=True)
    stderr_thread = threading.Thread(target=collect, args=(proc.stderr, stderr_lines), daemon=True)
    stdout_thread.start()
    stderr_thread.start()

    try:
        try:
            proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout_thread.join()
            stderr_thread.join()
            return {}, f"wall-clock timeout after {timeout_s}s", "".join(stdout_lines), "".join(stderr_lines)
        except BaseException:
            proc.kill()
            raise
    finally:
        _kill_container(container_name)

    stdout_thread.join()
    stderr_thread.join()
    stdout = "".join(stdout_lines)
    stderr = "".join(stderr_lines)

    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "solved" in parsed:
            return parsed, None, stdout, stderr

    return {}, (stdout.strip() or "no output from runner"), stdout, stderr


def _redact(cmd: list[str]) -> str:
    redacted: list[str] = []
    skip_next = False
    for part in cmd:
        if skip_next:
            key = part.split("=", 1)[0]
            redacted.append(f"{key}=<redacted>" if any(k in key for k in ("KEY", "TOKEN")) else part)
            skip_next = False
            continue
        redacted.append(part)
        if part == "-e":
            skip_next = True
    return " ".join(redacted)
