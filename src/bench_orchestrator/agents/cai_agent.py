from __future__ import annotations

import json
import os
import subprocess
import threading
import uuid
from pathlib import Path
from typing import Any

from bench_orchestrator.agents.base import AgentAdapter
from bench_orchestrator.agents.htb_flag_verify_server import FlagVerifyServer, build_verify_server
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
        # File-based challenges (StaticHostTargetProvider) have no live
        # endpoint - target.metadata["challenge_dir"] points at the
        # downloaded/extracted challenge files on the host instead. Mount it
        # into the container so the agent actually has something to analyse.
        # Mount point is parallel to the existing /opt/cai/logs and
        # /opt/cai/artifacts mounts below; named once here since both the
        # volume mount and the prompt text (via _build_env) must agree on it.
        challenge_dir = target.metadata.get("challenge_dir")
        challenge_mount = "/opt/cai/challenge" if challenge_dir else None
        flags_required = int(target.metadata.get("required_flags", 1))
        env = _build_env(
            manifest, target_desc, self.agent_config, self._api_keys,
            challenge_mount=challenge_mount, flags_required=flags_required,
        )

        if context.dry_run:
            recorder.event(
                "agent_completed",
                {"adapter": self.name, "dry_run": True, "env_keys": sorted(env)},
            )
            return AgentResult(status="completed", summary="Dry-run cai adapter execution.")

        # Gives the container's submit_flag tool (cai's
        # bench/submit_flag_tool.py) somewhere to get real HTB verification
        # instead of falling back to a local shape/exact match - see
        # htb_flag_verify_server.py. Not fatal if this can't be resolved
        # (e.g. a non-HTB task, or a name lookup failure): submit_flag
        # still works, just without real verification, same as before this
        # existed.
        verify_server: FlagVerifyServer | None = None
        htb_api_key = os.environ.get("HTB_API_KEY")
        if htb_api_key:
            try:
                verify_server = build_verify_server(manifest, target, htb_api_key)
            except Exception as exc:
                recorder.event("flag_verify_unavailable", {"adapter": self.name, "error": str(exc)})
        if verify_server is not None:
            verify_server.start()
            env["CHALLENGE_FLAG_VERIFY_URL"] = f"http://host.docker.internal:{verify_server.port}/verify"

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

        volumes = {str(log_dir): "/opt/cai/logs", str(artifacts_dir): "/opt/cai/artifacts"}
        if challenge_dir:
            volumes[str(Path(challenge_dir).resolve())] = challenge_mount

        # Named so a timeout can `docker kill` the container itself, not just
        # the local `docker run` client - see _docker_run.
        container_name = f"cai-bench-{uuid.uuid4().hex[:12]}"
        cmd = _build_docker_cmd(
            image=self.image,
            env=env,
            network=network,
            volumes=volumes,
            container_name=container_name,
        )
        try:
            result, error, stdout, stderr = _docker_run(cmd, timeout_s=timeout, container_name=container_name)
        finally:
            # Only needed while the container might still call back into
            # it - stop it the moment _docker_run returns, on every exit
            # path (success, error, or an exception unwinding through
            # here), rather than leaving it listening for the rest of run().
            if verify_server is not None:
                verify_server.stop()

        recorder.command(
            _redact(cmd),
            return_code=0 if error is None else 1,
            stdout=stdout,
            stderr=stderr,
            timeout_seconds=timeout,
        )
        if stdout:
            recorder.transcript(role="agent", content=stdout, metadata={"adapter": self.name})

        # cai writes its own full session transcript here (mounted from
        # log_dir above) - much richer than the one-line summary below,
        # which only ever contains cai's own already-decided flag guess(es).
        # Scorers need this to have any chance of finding a flag cai itself
        # missed or mis-extracted (confirmed live: cai's local regex can
        # grab garbage), and to check more than one candidate for
        # multi-flag targets. Attached on both outcomes below - a
        # cai-reported "failed"/timed-out run can still have found
        # something worth scoring in its transcript before it gave up.
        log_artifacts = [str(p) for p in sorted(log_dir.glob("*.jsonl"))]

        if error is not None:
            recorder.event("agent_completed", {"adapter": self.name, "status": "failed", "error": error})
            status = "timed_out" if "timeout" in error else "failed"
            return AgentResult(status=status, summary=f"cai run failed: {error}", metadata={"error": error}, artifacts=log_artifacts)

        solved = bool(result.get("solved"))
        summary = (
            f"cai {'solved' if solved else 'did not solve'} the task in "
            f"{result.get('turns')} turns ({result.get('stopped_reason')}). "
            f"Flags found: {result.get('flags')}"
        )
        recorder.event("agent_completed", {"adapter": self.name, "status": "completed" if solved else "failed", "result": result})
        return AgentResult(
            status="completed" if solved else "failed",
            summary=summary,
            metadata=result,
            artifacts=log_artifacts,
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
    challenge_mount: str | None = None,
    flags_required: int = 1,
) -> dict[str, str]:
    task = str(manifest.raw.get("task", "")).strip()
    if challenge_mount:
        # File-based challenge: no live target, just files mounted in the
        # container - tell the agent where, instead of an empty "Target: ".
        suffix = f"Challenge files are in {challenge_mount} (already extracted)."
    else:
        suffix = f"Target: {target_desc}"
    prompt = f"{task}\n\n{suffix}" if task else suffix

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
        "CHALLENGE_FLAGS_REQUIRED": str(flags_required),
        **api_keys,
    }
    flag_pattern = _flag_pattern(manifest)
    if flag_pattern:
        env["CHALLENGE_FLAG_PATTERN"] = flag_pattern
    if target_desc:
        env["TARGET_HOST"] = target_desc
    return env


def _flag_pattern(manifest: Manifest) -> str | None:
    # Not gated on scorer type - "pattern" is used for the container's
    # CHALLENGE_FLAG_PATTERN env var regardless of which scorer actually
    # decides pass/fail. verified_flags manifests still carry a pattern
    # here: it's submit_flag_tool's own local-verification fallback (used
    # when CHALLENGE_FLAG_VERIFY_URL isn't set), not something the scorer
    # itself reads anymore.
    for entry in manifest.raw.get("goal", {}).get("success", []):
        if entry.get("pattern"):
            return str(entry["pattern"])
    return None


def _build_docker_cmd(
    image: str,
    env: dict[str, str],
    network: str | None,
    volumes: dict[str, str],
    container_name: str,
) -> list[str]:
    cmd = ["docker", "run", "--rm", "--name", container_name]
    # The image's nmap (and other scanners) carry file capabilities
    # (cap_net_admin,cap_net_raw=eip on /usr/lib/nmap/nmap). Docker's default
    # bounding set has NET_RAW but not NET_ADMIN, and the kernel refuses to
    # exec a binary whose file caps aren't all in the bounding set - so nmap
    # dies with "Operation not permitted" before it even starts. Grant the
    # two net caps its scans need (not --privileged); the target is
    # authorised and the container is disposable.
    cmd += ["--cap-add=NET_ADMIN", "--cap-add=NET_RAW"]
    # Lets the container reach a verification server bound on the host (see
    # htb_flag_verify_server.py) via host.docker.internal, regardless of
    # network mode - needed because most targets don't use --network=host,
    # where the container's own 127.0.0.1 isn't the host's. host-gateway is
    # a real routable address on both bridge and host networking, so this
    # is harmless to always add even when nothing's actually listening.
    cmd += ["--add-host=host.docker.internal:host-gateway"]
    if network:
        cmd += [f"--network={network}"]
    for key, value in env.items():
        cmd += ["-e", f"{key}={value}"]
    for host_path, container_path in volumes.items():
        cmd += ["-v", f"{host_path}:{container_path}"]
    cmd.append(image)
    return cmd


def _kill_container(container_name: str) -> None:
    """Best-effort `docker kill` on a named container.

    `--rm` only removes a container that exits/stops on its own; killing the
    local `docker run` client (proc.kill() below) does not stop the daemon
    side of it - the container keeps running orphaned, still holding
    whatever network listeners the agent started. Since the container is
    named at launch, we can reach it directly regardless of how _docker_run
    exits. A missing container (the normal-completion case, already reaped
    by --rm) is expected and silently ignored.
    """
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
        try:
            proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout_thread.join()
            stderr_thread.join()
            return {}, f"wall-clock timeout after {timeout_s}s", "".join(stdout_lines), "".join(stderr_lines)
        except BaseException:
            # KeyboardInterrupt or anything else unwinding _docker_run early -
            # the container must not outlive it. Kill the local client too so
            # we don't leave it attached to a container we're about to kill.
            proc.kill()
            raise
    finally:
        # Covers every exit path, including the two above: on normal
        # completion the container is already gone (--rm) and this is a
        # harmless no-op; on timeout or an exception it's the actual fix.
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
