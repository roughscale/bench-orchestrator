from __future__ import annotations

import json
import os
import subprocess
import threading
from pathlib import Path
from typing import Any

from bench_orchestrator.agents.base import AgentAdapter
from bench_orchestrator.evidence import RunRecorder
from bench_orchestrator.models import AgentResult, Manifest, RunContext, TargetHandle

# Same set cai's own bench/orchestrator.py forwards - whichever of these are
# set on the host get passed into the container so the configured model can
# authenticate.
_API_KEY_VARS = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "DEEPSEEK_API_KEY", "GEMINI_API_KEY", "ALIAS_API_KEY")

_DEFAULT_IMAGE = "cai-bench:latest"


class CaiAgentAdapter(AgentAdapter):
    """Adapter for the CAI (Cybersecurity AI) framework's bench harness.

    Unlike pentest-agent/VulnBot, cai-bench is already a self-contained,
    one-shot batch script (bench/runner.py): it reads its task from env vars,
    runs to completion or CAI_MAX_TURNS, and prints one JSON result line to
    stdout before exiting. So this adapter runs a single `docker run --rm`
    per task rather than starting a long-lived container to exec into - the
    same contract cai's own bench/orchestrator.py already uses and relies on.
    """

    name = "cai"

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

        api_keys = {k: os.environ[k] for k in _API_KEY_VARS if k in os.environ}
        if not api_keys:
            raise RuntimeError(
                f"cai adapter requires at least one of {', '.join(_API_KEY_VARS)} to be set"
            )
        self._api_keys = api_keys
        recorder.event("agent_prepared", {"adapter": self.name, "image": self.image})

    def run(
        self,
        manifest: Manifest,
        target: TargetHandle,
        context: RunContext,
        recorder: RunRecorder,
    ) -> AgentResult:
        target_desc = target.endpoint or manifest.raw.get("target", {}).get("host", "")
        env = _build_env(manifest, target_desc, self.agent_config, self._api_keys)

        if context.dry_run:
            recorder.event(
                "agent_completed",
                {"adapter": self.name, "dry_run": True, "env_keys": sorted(env)},
            )
            return AgentResult(status="completed", summary="Dry-run cai adapter execution.")

        log_dir = (context.log_dir / "target_logs" / "cai" / "logs").resolve()
        log_dir.mkdir(parents=True, exist_ok=True)
        artifacts_dir = (recorder.artifact_dir / "cai").resolve()
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        # target.network_mode takes precedence over network_name - it's how a
        # provider says "the agent needs the host's own network namespace",
        # which doesn't fit the "join a named bridge" model network_name
        # expresses (see HtbTargetProvider and TargetHandle.network_mode).
        network = target.network_mode or target.network_name
        timeout = int(self.agent_config.get("timeout_seconds", 3600))

        recorder.event("agent_started", {"adapter": self.name, "network": network, "timeout_seconds": timeout})

        cmd = _build_docker_cmd(
            image=self.image,
            env=env,
            network=network,
            volumes={str(log_dir): "/opt/cai/logs", str(artifacts_dir): "/opt/cai/artifacts"},
        )
        result, error, stdout, stderr = _docker_run(cmd, timeout_s=timeout)

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
            return AgentResult(status=status, summary=f"cai run failed: {error}", metadata={"error": error})

        solved = bool(result.get("solved"))
        summary = (
            f"cai {'solved' if solved else 'did not solve'} the task in "
            f"{result.get('turns')} turns ({result.get('stopped_reason')}). "
            f"Flag: {result.get('flag')}"
        )
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

def _build_env(
    manifest: Manifest,
    target_desc: str,
    agent_config: dict[str, Any],
    api_keys: dict[str, str],
) -> dict[str, str]:
    task = str(manifest.raw.get("task", "")).strip()
    prompt = f"{task}\n\nTarget: {target_desc}" if task else f"Target: {target_desc}"

    env = {
        "CHALLENGE_PROMPT": prompt,
        "CAI_MODEL": str(agent_config.get("model", "alias0")),
        "CAI_AGENT_TYPE": str(agent_config.get("agent_type", "redteam_agent")),
        "CAI_MAX_TURNS": str(agent_config.get("max_turns", 100)),
        "CAI_STREAM": "false",
        # See bench/orchestrator.py's _build_runner_env: guardrails default
        # off for authorized bench targets, reasoning effort low to control
        # cost - both overridable per agent_config.
        "CAI_GUARDRAILS": str(agent_config.get("guardrails", False)).lower(),
        "CAI_REASONING_EFFORT": str(agent_config.get("reasoning_effort", "low")),
        **api_keys,
    }
    flag_pattern = _flag_pattern(manifest)
    if flag_pattern:
        env["CHALLENGE_FLAG_PATTERN"] = flag_pattern
    if target_desc:
        env["TARGET_HOST"] = target_desc
    return env


def _flag_pattern(manifest: Manifest) -> str | None:
    for entry in manifest.raw.get("goal", {}).get("success", []):
        if entry.get("type") == "flag_pattern":
            return str(entry.get("pattern")) if entry.get("pattern") else None
    return None


def _build_docker_cmd(
    image: str,
    env: dict[str, str],
    network: str | None,
    volumes: dict[str, str],
) -> list[str]:
    cmd = ["docker", "run", "--rm"]
    if network:
        cmd += [f"--network={network}"]
    for key, value in env.items():
        cmd += ["-e", f"{key}={value}"]
    for host_path, container_path in volumes.items():
        cmd += ["-v", f"{host_path}:{container_path}"]
    cmd.append(image)
    return cmd


def _docker_run(cmd: list[str], timeout_s: int) -> tuple[dict[str, Any], str | None, str, str]:
    """Run the cai-bench container; stream stderr, parse the trailing JSON stdout line.

    Same contract as cai's own bench/orchestrator.py::_docker_run - the
    runner script can print progress/log noise to stdout ahead of its final
    result, so the last line that parses as JSON and looks like a result
    (has a "solved" key) is taken as the answer.
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
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout_thread.join()
        stderr_thread.join()
        return {}, f"wall-clock timeout after {timeout_s}s", "".join(stdout_lines), "".join(stderr_lines)

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
