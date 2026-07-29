from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any

import yaml

from bench_orchestrator.agents.base import AgentAdapter
from bench_orchestrator.evidence import RunRecorder
from bench_orchestrator.models import AgentResult, Manifest, RunContext, TargetHandle


# VulnBot runs on the attacker network alongside Kali and MySQL.
# Kali bridges this network and bench_target so it can reach the target.
_ATTACKER_NETWORK = "bench_attacker"

# Infrastructure compose file is co-located with this adapter package.
COMPOSE_FILE = Path(__file__).parent / "docker-compose.yml"

_FORWARDED_ENV = [
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "VULNBOT_API_KEY",
    "VULNBOT_BASE_URL",
    "VULNBOT_LLM_MODEL",
    "VULNBOT_LLM_MODEL_NAME",
]
_CONTAINER_WORKDIR = "/app"
_CONTAINER_PENTEST_ROOT = "/workspace/vulnbot"
_FLAG_RE = re.compile(r"(?P<flag>(?:[A-Z0-9_]+)?\{[^{}\n]{3,}\})")
_SESSION_RE = re.compile(r"current session is saved with the name\s+(?P<session>\S+)", re.IGNORECASE)


class VulnBotAdapter(AgentAdapter):
    """Adapter for Brenton's roughscale VulnBot fork.

    VulnBot is an interactive Click/prompt-toolkit harness. This adapter runs it
    in a long-lived Docker container, mounts a per-run PENTEST_ROOT, writes the
    minimal runtime config files, and feeds the task description through stdin.
    """

    name = "vulnbot"

    def __init__(
        self,
        image: str = "vulnbot:latest",
        agent_config: dict[str, Any] | None = None,
    ) -> None:
        self.image = image
        self._agent_config: dict[str, Any] = agent_config or {}
        self._container_name: str | None = None
        self._workspace_dir: Path | None = None

    @property
    def model_name(self) -> str | None:
        return self._agent_config.get("model") or None

    @property
    def compose_file(self) -> Path:
        return COMPOSE_FILE

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

        container_name = _container_name(context.run_id)
        workspace_dir = recorder.artifact_dir / "vulnbot_workspace"
        workspace_dir.mkdir(parents=True, exist_ok=True)
        write_vulnbot_config(manifest, target, workspace_dir, self._agent_config)

        _docker_run(
            container_name=container_name,
            image=self.image,
            network=_ATTACKER_NETWORK,
            workspace_dir=workspace_dir,
            env_values=_env_values(self._agent_config),
            recorder=recorder,
        )
        if self._agent_config.get("init_db", True):
            _initialize_vulnbot_database(container_name, recorder)

        self._container_name = container_name
        self._workspace_dir = workspace_dir
        recorder.event(
            "agent_prepared",
            {
                "adapter": self.name,
                "container": container_name,
                "image": self.image,
                "workspace_dir": str(workspace_dir),
                "target": resolve_target(manifest, target, self._agent_config),
            },
        )

    def run(
        self,
        manifest: Manifest,
        target: TargetHandle,
        context: RunContext,
        recorder: RunRecorder,
    ) -> AgentResult:
        command = build_vulnbot_command(self._agent_config)
        stdin = build_vulnbot_stdin(manifest, target, self._agent_config, context)
        timeout = _timeout_seconds(self._agent_config)

        if context.dry_run:
            recorder.event(
                "agent_completed",
                {
                    "adapter": self.name,
                    "dry_run": True,
                    "command": " ".join(command),
                    "timeout_seconds": timeout,
                },
            )
            return AgentResult(
                status="completed",
                summary="Dry-run VulnBot adapter execution.",
                metadata={"command": command, "target": resolve_target(manifest, target, self._agent_config)},
            )

        if self._container_name is None:
            raise RuntimeError("VulnBot adapter was not prepared")

        recorder.event(
            "agent_started",
            {
                "adapter": self.name,
                "command": " ".join(command),
                "timeout_seconds": timeout,
            },
        )
        result = _docker_exec(
            self._container_name,
            command,
            stdin=stdin,
            workdir=_CONTAINER_WORKDIR,
            timeout=timeout,
        )

        recorder.command(
            f"docker exec -i {self._container_name} {' '.join(command)}",
            return_code=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            timeout_seconds=timeout,
            container=self._container_name,
        )
        recorder.transcript(
            role="agent",
            content=result.stdout,
            metadata={"adapter": self.name, "return_code": result.returncode},
        )

        stdout_path = recorder.artifact_path("vulnbot.stdout.log")
        stderr_path = recorder.artifact_path("vulnbot.stderr.log")
        stdout_path.write_text(result.stdout or "", encoding="utf-8")
        stderr_path.write_text(result.stderr or "", encoding="utf-8")
        artifacts = [str(stdout_path), str(stderr_path)]
        if self._workspace_dir is not None:
            artifacts.append(str(self._workspace_dir))

        metadata = parse_vulnbot_output(result.stdout)
        metadata.update(
            {
                "command": command,
                "return_code": result.returncode,
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
                "target": resolve_target(manifest, target),
            }
        )

        if result.returncode == 124:
            status = "timed_out"
            summary = f"VulnBot timed out after {timeout}s."
        elif result.returncode == 0:
            status = "completed"
            summary = _summary(metadata)
        else:
            status = "failed"
            summary = f"VulnBot exited with code {result.returncode}. {_summary(metadata)}"

        recorder.event(
            "agent_completed",
            {
                "adapter": self.name,
                "status": status,
                "return_code": result.returncode,
                "metadata": metadata,
            },
        )
        return AgentResult(status=status, summary=summary, artifacts=artifacts, metadata=metadata)

    def stop(self, recorder: RunRecorder) -> None:
        if self._container_name is None:
            return
        for args in (
            ["docker", "stop", self._container_name],
            ["docker", "rm", self._container_name],
        ):
            result = subprocess.run(args, capture_output=True, text=True, check=False)
            recorder.command(
                " ".join(args),
                return_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                container=self._container_name,
            )
        recorder.event("agent_stopped", {"adapter": self.name, "container": self._container_name})
        self._container_name = None


def build_vulnbot_command(agent_config: dict[str, Any]) -> list[str]:
    cfg = agent_config
    command = cfg.get("command")
    if command:
        if not isinstance(command, list):
            raise ValueError("vulnbot agent config 'command' must be a list of strings")
        return [str(part) for part in command]

    max_interactions = int(cfg.get("max_interactions", 5))
    cli_path = str(cfg.get("cli_path", "cli.py"))
    return ["python", "-u", cli_path, "vulnbot", "-m", str(max_interactions)]


def build_vulnbot_stdin(manifest: Manifest, target: TargetHandle, agent_config: dict[str, Any], context: RunContext | None = None) -> str:
    cfg = agent_config
    session_name = str(cfg.get("session_name") or (context.run_id if context else manifest.id.replace("/", "_")))

    # prompt_toolkit's confirm() reads a single character ('n'), not a full line.
    # A newline separator between 'n' and the task description would be left in
    # the buffer and consumed by the task prompt as an empty line, shifting the
    # instruction to the session-save prompt.  Concatenate 'n' directly with
    # the instruction so the task prompt reads the correct input.
    #
    # Sequence:
    #   1. confirm() → 'n'  (no trailing newline consumed)
    #   2. prompt(task) → instruction
    #   3. prompt(session name) → session_name
    # Some manifest task fields contain embedded newlines (e.g. network_security,
    # real-world/cve categories append a hint on a second line).  A newline inside
    # the instruction would be consumed by the task prompt as a line terminator,
    # shifting the session-name input to the wrong prompt.  Collapse to a single line.
    task_instruction = instruction(manifest, target, agent_config).replace("\n", " ")
    return f"n{task_instruction}\n{session_name}\n"


def parse_vulnbot_output(stdout: str) -> dict[str, Any]:
    text = stdout or ""
    flags = sorted(set(_FLAG_RE.findall(text)))
    metadata: dict[str, Any] = {"flags": flags, "flag_count": len(flags)}
    session_match = _SESSION_RE.search(text)
    if session_match:
        metadata["session_name"] = session_match.group("session")
    return metadata


def write_vulnbot_config(manifest: Manifest, target: TargetHandle, workspace_dir: Path, agent_config: dict[str, Any] | None = None) -> None:
    cfg = agent_config or {}
    workspace_dir.mkdir(parents=True, exist_ok=True)

    basic = {
        "log_verbose": bool(cfg.get("log_verbose", True)),
        "enable_rag": bool(cfg.get("enable_rag", False)),
        "mode": str(cfg.get("mode", "auto")),
        "KB_ROOT_PATH": str(cfg.get("kb_root_path", f"{_CONTAINER_PENTEST_ROOT}/data/knowledge_base")),
        "http_default_timeout": int(cfg.get("http_default_timeout", 300)),
        "kali": _kali_config(cfg),
        "api_server": cfg.get(
            "api_server",
            {"host": "0.0.0.0", "port": 7861, "public_host": "127.0.0.1", "public_port": 7861},
        ),
        "webui_server": cfg.get("webui_server", {"host": "0.0.0.0", "port": 8501}),
    }
    db = {"mysql": _db_config(cfg)}
    kb = {
        "default_vs_type": str(cfg.get("default_vs_type", "milvus")),
        "milvus": cfg.get("milvus", {"uri": "", "user": "", "password": ""}),
        "kb_name": str(cfg.get("kb_name", "")),
        "chunk_size": int(cfg.get("chunk_size", 750)),
        "overlap_size": int(cfg.get("overlap_size", 150)),
        "top_n": int(cfg.get("top_n", 1)),
        "top_k": int(cfg.get("top_k", 3)),
        "score_threshold": float(cfg.get("score_threshold", 0.5)),
    }
    # Resolve API key: prefer explicit value in config, then a named env var
    # (api_key_env), then the standard fallback env vars.
    api_key = (
        cfg.get("api_key")
        or os.environ.get(cfg.get("api_key_env", ""), "")
        or os.environ.get("VULNBOT_API_KEY", "")
        or os.environ.get("OPENAI_API_KEY", "")
    )
    llm = {
        "api_key": str(api_key),
        "llm_model": str(cfg.get("llm_model", os.environ.get("VULNBOT_LLM_MODEL", "openai"))),
        "base_url": str(cfg.get("base_url", os.environ.get("VULNBOT_BASE_URL", os.environ.get("OPENAI_BASE_URL", "")))),
        "llm_model_name": str(cfg.get("model", os.environ.get("VULNBOT_LLM_MODEL_NAME", ""))),
        "embedding_models": str(cfg.get("embedding_models", "maidalun1020/bce-embedding-base_v1")),
        "embedding_type": str(cfg.get("embedding_type", "local")),
        "context_length": int(cfg.get("context_length", 120000)),
        "embedding_url": str(cfg.get("embedding_url", "")),
        "rerank_model": str(cfg.get("rerank_model", "maidalun1020/bce-reranker-base_v1")),
        "temperature": float(cfg.get("temperature", 0.5)),
        "history_len": int(cfg.get("history_len", 5)),
        "timeout": int(cfg.get("llm_timeout", 600)),
        "proxies": cfg.get("proxies", {}),
    }

    for name, payload in {
        "basic_config.yaml": basic,
        "db_config.yaml": db,
        "kb_config.yaml": kb,
        "model_config.yaml": llm,
    }.items():
        (workspace_dir / name).write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    (workspace_dir / "logs").mkdir(exist_ok=True)
    (workspace_dir / "data" / "knowledge_base").mkdir(parents=True, exist_ok=True)


def resolve_target(manifest: Manifest, target: TargetHandle, agent_config: dict[str, Any] | None = None) -> str:
    cfg = agent_config or {}
    if cfg.get("target"):
        return str(cfg["target"])
    if target.endpoint:
        return target.endpoint

    alias = target.target_alias or target.metadata.get("host") or "target"
    ports = manifest.raw.get("network", {}).get("exposed_ports", [])
    port = str(ports[0]).split("/")[0] if ports else ""
    scheme = cfg.get("scheme")
    if scheme and port:
        return f"{scheme}://{alias}:{port}"
    if scheme:
        return f"{scheme}://{alias}"
    if port:
        return f"{alias}:{port}"
    return str(alias)


def instruction(manifest: Manifest, target: TargetHandle, agent_config: dict[str, Any] | None = None) -> str:
    cfg = agent_config or {}
    if cfg.get("instruction"):
        return str(cfg["instruction"])

    target_host = target.target_alias or "target"
    parts = [
        "Authorized benchmark target. Operate only against the supplied lab target.",
        f"Target: {resolve_target(manifest, target, agent_config)}.",
    ]

    task = manifest.raw.get("task", "")
    if task:
        # Render {target_host} and {target_net} placeholders.
        # {target_net}  — the CIDR range the agent should scan.
        # {target_host} — the attacker's own IP on that network (Kali), which the
        #                 agent should exclude from scans so it doesn't scan itself.
        #                 This is NOT the target's IP; that would tell the agent to
        #                 skip the very machine it needs to find.
        target_ip = target.metadata.get("target_ip") or target_host
        target_net = target.metadata.get("target_net") or target_ip
        attacker_ip = target.metadata.get("attacker_ip") or target_host
        try:
            task = task.format(target_host=attacker_ip, target_net=target_net)
        except (KeyError, ValueError):
            pass
        parts.append(f"Task: {task}")

    goal = manifest.raw.get("goal", {})
    if goal.get("kind") and not task:
        parts.append(f"Goal: {goal['kind']}.")
    if goal.get("description"):
        parts.append(str(goal["description"]))
    if manifest.raw.get("difficulty"):
        parts.append(f"Difficulty: {manifest.raw['difficulty']}.")
    return " ".join(parts)




def _kali_config(cfg: dict[str, Any]) -> dict[str, Any]:
    kali = dict(cfg.get("kali", {}))
    return {
        "hostname": str(kali.get("hostname", cfg.get("kali_host", "kali"))),
        "port": int(kali.get("port", cfg.get("kali_port", 22))),
        "username": str(kali.get("username", cfg.get("kali_username", "root"))),
        "password": str(kali.get("password", cfg.get("kali_password", "root"))),
    }


def _db_config(cfg: dict[str, Any]) -> dict[str, Any]:
    db = dict(cfg.get("mysql", cfg.get("db", {})))
    return {
        "host": str(db.get("host", cfg.get("db_host", os.environ.get("VULNBOT_DB_HOST", "mysql")))),
        "port": int(db.get("port", cfg.get("db_port", os.environ.get("VULNBOT_DB_PORT", 3306)))),
        "user": str(db.get("user", cfg.get("db_user", os.environ.get("VULNBOT_DB_USER", "vulnbot")))),
        "password": str(db.get("password", cfg.get("db_password", os.environ.get("VULNBOT_DB_PASSWORD", "vulnbot")))),
        "database": str(db.get("database", cfg.get("db_database", os.environ.get("VULNBOT_DB_DATABASE", "vulnbot")))),
    }


def _timeout_seconds(agent_config: dict[str, Any]) -> int:
    return int(agent_config.get("timeout_seconds", 3600))


def _container_name(run_id: str) -> str:
    slug = "".join(ch if ch.isalnum() else "_" for ch in run_id.lower()).strip("_")
    return f"vulnbot_{slug}"[:63]


def _docker_run(
    *,
    container_name: str,
    image: str,
    network: str | None,
    workspace_dir: Path,
    env_values: dict[str, str],
    recorder: RunRecorder,
) -> None:
    cmd = [
        "docker",
        "run",
        "-d",
        "--name",
        container_name,
        "--cap-add",
        "NET_RAW",
        "--cap-add",
        "NET_ADMIN",
        "--cap-add",
        "SYS_PTRACE",
        "-v",
        f"{workspace_dir}:{_CONTAINER_PENTEST_ROOT}",
        "-e",
        f"PENTEST_ROOT={_CONTAINER_PENTEST_ROOT}",
    ]
    if network:
        cmd += ["--network", network]
    for key, value in env_values.items():
        cmd += ["-e", f"{key}={value}"]

    cmd += [image, "sleep", "infinity"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    recorder.command(
        _redact_command(cmd),
        return_code=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )
    if result.returncode != 0:
        raise RuntimeError(f"failed to start VulnBot container: {result.stderr.strip()}")


def _docker_exec(
    container_name: str,
    command: list[str],
    *,
    stdin: str,
    workdir: str,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    full_cmd = ["docker", "exec", "-i", "-w", workdir, container_name, *command]
    try:
        return subprocess.run(
            full_cmd,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        # exc.stdout / exc.stderr can be bytes even when text=True is passed to
        # subprocess.run — Python captures partial output before decoding when a
        # timeout fires.  Decode defensively to avoid a TypeError on concatenation.
        def _to_str(b: bytes | str | None) -> str:
            if isinstance(b, bytes):
                return b.decode(errors="replace")
            return b or ""

        return subprocess.CompletedProcess(
            args=full_cmd,
            returncode=124,
            stdout=_to_str(exc.stdout),
            stderr=_to_str(exc.stderr) + f"\nVulnBot timed out after {timeout}s",
        )


def _initialize_vulnbot_database(container_name: str, recorder: RunRecorder) -> None:
    # `cli.py init` imports all SQLAlchemy model modules before calling
    # create_tables(), which is required for Base.metadata to know about
    # all tables. A bare create_tables() call without the model imports
    # produces an empty schema.
    cmd = [
        "docker",
        "exec",
        "-w",
        _CONTAINER_WORKDIR,
        container_name,
        "python",
        "-u",
        "cli.py",
        "init",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
    recorder.command(
        " ".join(cmd),
        return_code=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
        timeout_seconds=120,
        container=container_name,
    )
    if result.returncode != 0:
        raise RuntimeError(f"failed to initialize VulnBot database: {result.stderr.strip()}")


def _env_values(agent_config: dict[str, Any]) -> dict[str, str]:
    cfg = agent_config
    values = {key: value for key in _FORWARDED_ENV if (value := os.environ.get(key))}

    api_key_env = str(cfg.get("api_key_env", ""))
    if api_key_env and os.environ.get(api_key_env):
        values["API_KEY"] = os.environ[api_key_env]
    elif os.environ.get("VULNBOT_API_KEY"):
        values["API_KEY"] = os.environ["VULNBOT_API_KEY"]
    elif os.environ.get("OPENAI_API_KEY"):
        values["API_KEY"] = os.environ["OPENAI_API_KEY"]

    if cfg.get("base_url"):
        values["BASE_URL"] = str(cfg["base_url"])
    if cfg.get("llm_model"):
        values["LLM_MODEL"] = str(cfg["llm_model"])
    if cfg.get("model"):
        values["LLM_MODEL_NAME"] = str(cfg["model"])
    return values


def _redact_command(cmd: list[str]) -> str:
    redacted: list[str] = []
    skip_next = False
    for part in cmd:
        if skip_next:
            key = part.split("=", 1)[0]
            redacted.append(f"{key}=<redacted>" if "=" in part else "<redacted>")
            skip_next = False
            continue
        redacted.append(part)
        if part == "-e":
            skip_next = True
    return " ".join(redacted)


def _summary(metadata: dict[str, Any]) -> str:
    session = metadata.get("session_name", "")
    suffix = f", session {session}" if session else ""
    return f"VulnBot completed with {metadata.get('flag_count', 0)} flag(s){suffix}."
