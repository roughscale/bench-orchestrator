from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import yaml

from bench_orchestrator.evidence import RunRecorder
from bench_orchestrator.models import HealthStatus, Manifest, RunContext, TargetHandle, dump_manifest
from bench_orchestrator.targets.base import TargetProvider


COMPOSE_FILENAMES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")


class VulhubManifestGenerator:
    """Generate draft manifests from a local Vulhub tree."""

    def __init__(self, vulhub_root: Path):
        self.vulhub_root = vulhub_root

    def generate(self) -> list[dict[str, Any]]:
        manifests: list[dict[str, Any]] = []
        for compose_file in find_compose_files(self.vulhub_root):
            scenario_dir = compose_file.parent
            rel = scenario_dir.relative_to(self.vulhub_root)
            manifest_id = "vulhub/" + "/".join(part.lower() for part in rel.parts)
            ports = extract_ports(compose_file)
            first_port = ports[0] if ports else "80/tcp"
            manifests.append(
                {
                    "id": manifest_id,
                    "provider": "vulhub",
                    "source_dir": str(scenario_dir),
                    "difficulty": "unknown",
                    "category": "unknown",
                    "network": {
                        "target_alias": "target",
                        "exposed_ports": ports,
                    },
                    "target": {
                        "startup_timeout_seconds": 120,
                        "health": default_health_checks(first_port),
                    },
                    "agent": {
                        "adapter": "pentest-agent",
                        "max_iterations": 30,
                        "timeout_seconds": 3600,
                    },
                    "goal": {
                        "kind": "functional_exploit",
                        "success": [{"type": "needs_curation"}],
                    },
                    "evidence": {
                        "save_container_logs": True,
                        "capture_pcaps": False,
                    },
                    "curation": {
                        "status": "needs_success_criteria",
                        "notes": "Generated from Vulhub inventory. Curate exploit goal and scorers before benchmark use.",
                    },
                }
            )
        return manifests

    def write(self, output_dir: Path) -> list[Path]:
        paths: list[Path] = []
        for manifest in self.generate():
            rel_id = manifest["id"].removeprefix("vulhub/")
            path = output_dir / f"{rel_id}.generated.yaml"
            dump_manifest(manifest, path)
            paths.append(path)
        return paths


class VulhubTargetProvider(TargetProvider):
    name = "vulhub"

    def prepare(self, manifest: Manifest, context: RunContext, recorder: RunRecorder) -> None:
        source_dir = require_source_dir(manifest)
        if not any((source_dir / name).exists() for name in COMPOSE_FILENAMES):
            raise FileNotFoundError(f"no compose file found in {source_dir}")
        recorder.event("target_prepared", {"provider": self.name, "source_dir": str(source_dir)})

    def start(self, manifest: Manifest, context: RunContext, recorder: RunRecorder) -> TargetHandle:
        source_dir = require_source_dir(manifest)
        project_name = docker_project_name(context.run_id, manifest.id)
        network_name = f"bench_{context.run_id}"
        target_alias = manifest.raw.get("network", {}).get("target_alias", "target")
        if context.dry_run:
            recorder.event(
                "target_started",
                {"dry_run": True, "project_name": project_name, "network_name": network_name},
            )
            return TargetHandle(
                provider=self.name,
                target_id=manifest.id,
                network_name=network_name,
                target_alias=target_alias,
                metadata={"project_name": project_name, "source_dir": str(source_dir)},
            )

        run_command(["docker", "network", "create", network_name], recorder, check=False)
        run_command(
            ["docker", "compose", "-p", project_name, "up", "-d", "--remove-orphans"],
            recorder,
            cwd=source_dir,
        )
        recorder.event("target_started", {"project_name": project_name, "network_name": network_name})
        return TargetHandle(
            provider=self.name,
            target_id=manifest.id,
            network_name=network_name,
            target_alias=target_alias,
            metadata={"project_name": project_name, "source_dir": str(source_dir)},
        )

    def healthcheck(self, handle: TargetHandle, manifest: Manifest, recorder: RunRecorder) -> HealthStatus:
        checks = manifest.raw.get("target", {}).get("health", [])
        recorder.event("target_healthy", {"status": "not_implemented", "checks": checks})
        return HealthStatus(ready=True, checks=checks, message="Health checks are recorded but not yet actively probed.")

    def collect_logs(self, handle: TargetHandle, manifest: Manifest, recorder: RunRecorder) -> None:
        source_dir = Path(handle.metadata.get("source_dir", require_source_dir(manifest)))
        project_name = handle.metadata.get("project_name")
        if not project_name:
            return
        output = recorder.target_log_dir / "docker-compose.log"
        if recorder.context.dry_run:
            output.write_text("dry-run: docker compose logs not collected\n", encoding="utf-8")
            return
        result = run_command(
            ["docker", "compose", "-p", str(project_name), "logs", "--no-color"],
            recorder,
            cwd=source_dir,
            check=False,
        )
        output.write_text(result.stdout or "", encoding="utf-8")

    def stop(self, handle: TargetHandle, manifest: Manifest, recorder: RunRecorder) -> None:
        source_dir = Path(handle.metadata.get("source_dir", require_source_dir(manifest)))
        project_name = handle.metadata.get("project_name")
        if project_name and not recorder.context.dry_run:
            run_command(["docker", "compose", "-p", str(project_name), "down", "--remove-orphans"], recorder, cwd=source_dir, check=False)
        if handle.network_name and not recorder.context.dry_run:
            run_command(["docker", "network", "rm", handle.network_name], recorder, check=False)
        recorder.event("teardown_completed", {"provider": self.name, "target_id": handle.target_id})


def find_compose_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for name in COMPOSE_FILENAMES:
        files.extend(path for path in root.rglob(name) if ".git" not in path.parts)
    return sorted(files)


def extract_ports(compose_file: Path) -> list[str]:
    try:
        data = yaml.safe_load(compose_file.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return []
    services = data.get("services", {}) if isinstance(data, dict) else {}
    ports: list[str] = []
    if not isinstance(services, dict):
        return ports
    for service in services.values():
        if not isinstance(service, dict):
            continue
        for port in service.get("ports", []) or []:
            normalized = normalize_port(port)
            if normalized and normalized not in ports:
                ports.append(normalized)
    return ports


def normalize_port(port: Any) -> str | None:
    if isinstance(port, int):
        return f"{port}/tcp"
    if isinstance(port, str):
        value = port.split("/")[:1][0]
        target = value.split(":")[-1]
        if target.isdigit():
            return f"{target}/tcp"
    if isinstance(port, dict):
        target = port.get("target") or port.get("published")
        protocol = port.get("protocol", "tcp")
        if target:
            return f"{target}/{protocol}"
    return None


def default_health_checks(first_port: str) -> list[dict[str, Any]]:
    port = first_port.split("/")[0]
    return [{"type": "tcp", "host": "target", "port": int(port)}] if port.isdigit() else []


def require_source_dir(manifest: Manifest) -> Path:
    source_dir = manifest.source_dir
    if source_dir is None:
        raise ValueError(f"manifest {manifest.id} is missing source_dir")
    return source_dir


def docker_project_name(run_id: str, manifest_id: str) -> str:
    slug = "".join(ch if ch.isalnum() else "_" for ch in manifest_id.lower()).strip("_")
    return f"bench_{run_id}_{slug}"[:63]


def run_command(
    args: list[str],
    recorder: RunRecorder,
    *,
    cwd: Path | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=False)
    recorder.command(" ".join(args), cwd=str(cwd) if cwd else None, return_code=result.returncode, stdout=result.stdout, stderr=result.stderr)
    if check and result.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(args)}")
    return result

