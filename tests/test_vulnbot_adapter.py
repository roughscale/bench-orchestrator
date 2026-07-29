from pathlib import Path

import yaml

from bench_orchestrator.agents.factory import build_agent_adapter
from bench_orchestrator.agents.vulnbot import (
    VulnBotAdapter,
    build_vulnbot_command,
    build_vulnbot_stdin,
    parse_vulnbot_output,
    resolve_target,
    write_vulnbot_config,
)
from bench_orchestrator.models import Manifest, RunContext, TargetHandle


def test_factory_builds_vulnbot_adapter_with_roughscale_image() -> None:
    adapter = build_agent_adapter("vulnbot", vulnbot_image="ghcr.io/roughscale/vulnbot:test")

    assert isinstance(adapter, VulnBotAdapter)
    assert adapter.image == "ghcr.io/roughscale/vulnbot:test"


def test_build_command_uses_agent_config() -> None:
    agent_config = {
        "max_interactions": 7,
        "cli_path": "/opt/VulnBot/cli.py",
    }

    assert build_vulnbot_command(agent_config) == [
        "python",
        "-u",
        "/opt/VulnBot/cli.py",
        "vulnbot",
        "-m",
        "7",
    ]


def test_build_stdin_declines_resume_and_injects_instruction() -> None:
    manifest = Manifest(
        raw={
            "id": "vulhub/example",
            "provider": "vulhub",
            "network": {"exposed_ports": ["8080/tcp"]},
        }
    )
    target = TargetHandle(provider="vulhub", target_id="vulhub/example", target_alias="target")
    agent_config = {"scheme": "http", "instruction": "Find the benchmark proof."}
    context = RunContext.create(Path("/tmp/bench"), run_id="run_123")

    # 'n' has no trailing newline: prompt_toolkit confirm() reads a single char,
    # so the instruction is concatenated directly to avoid an empty line shift.
    assert build_vulnbot_stdin(manifest, target, agent_config, context) == "nFind the benchmark proof.\nrun_123\n"


def test_resolve_target_derives_target_from_network_alias_and_port() -> None:
    manifest = Manifest(
        raw={
            "id": "vulhub/example",
            "provider": "vulhub",
            "network": {"exposed_ports": ["8080/tcp"]},
        }
    )
    target = TargetHandle(provider="vulhub", target_id="vulhub/example", target_alias="target")
    agent_config = {"scheme": "http"}

    assert resolve_target(manifest, target, agent_config) == "http://target:8080"


def test_write_config_files_for_vulnbot_runtime(tmp_path: Path) -> None:
    manifest = Manifest(raw={"id": "lab/example", "provider": "static_host"})
    target = TargetHandle(provider="static_host", target_id="lab/example", endpoint="http://target")
    agent_config = {
        "model": "gpt-4o-mini",
        "base_url": "https://api.openai.com/v1",
        "kali": {
            "hostname": "kali",
            "port": 2222,
            "username": "pentester",
            "password": "secret",
        },
        "mysql": {
            "host": "mysql",
            "port": 3307,
            "user": "vulnbot",
            "password": "vulnbot",
            "database": "vulnbot",
        },
    }

    write_vulnbot_config(manifest, target, tmp_path, agent_config)

    basic = yaml.safe_load((tmp_path / "basic_config.yaml").read_text(encoding="utf-8"))
    db = yaml.safe_load((tmp_path / "db_config.yaml").read_text(encoding="utf-8"))
    model = yaml.safe_load((tmp_path / "model_config.yaml").read_text(encoding="utf-8"))

    assert basic["mode"] == "auto"
    assert basic["kali"]["hostname"] == "kali"
    assert basic["kali"]["port"] == 2222
    assert db["mysql"]["port"] == 3307
    assert model["llm_model_name"] == "gpt-4o-mini"
    assert model["base_url"] == "https://api.openai.com/v1"


def test_parse_vulnbot_output_extracts_flags_and_session() -> None:
    metadata = parse_vulnbot_output(
        """
Observation: captured HTB{abc123}
The current session is saved with the name run_123
"""
    )

    assert metadata == {
        "flags": ["HTB{abc123}"],
        "flag_count": 1,
        "session_name": "run_123",
    }
