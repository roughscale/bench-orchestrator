from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import yaml

from bench_orchestrator.evidence import RunRecorder
from bench_orchestrator.models import HealthStatus, Manifest, RunContext, TargetHandle, dump_manifest
from bench_orchestrator.targets.base import TargetProvider


COMPOSE_FILENAMES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")

# Fixed network shared by all target containers and the Kali attacker.
# Created and owned by the companion docker-compose.yml.
BENCH_TARGET_NETWORK = "bench_target"


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
        target_alias = manifest.raw.get("network", {}).get("target_alias", "target")
        if context.dry_run:
            recorder.event(
                "target_started",
                {"dry_run": True, "project_name": project_name, "network_name": BENCH_TARGET_NETWORK},
            )
            return TargetHandle(
                provider=self.name,
                target_id=manifest.id,
                network_name=BENCH_TARGET_NETWORK,
                target_alias=target_alias,
                metadata={"project_name": project_name, "source_dir": str(source_dir)},
            )

        try:
            run_command(
                ["docker", "compose", "-p", project_name, "up", "-d", "--remove-orphans"],
                recorder,
                cwd=source_dir,
            )

            # Connect all target containers to bench_target so Kali and agent
            # containers on that network can reach the target by alias.
            primary_container_id = _attach_compose_to_network(
                project_name, BENCH_TARGET_NETWORK, target_alias, manifest, recorder
            )
        except Exception:
            run_command(
                ["docker", "compose", "-p", project_name, "down", "--remove-orphans"],
                recorder,
                cwd=source_dir,
                check=False,
            )
            raise

        recorder.event(
            "target_started",
            {
                "project_name": project_name,
                "network_name": BENCH_TARGET_NETWORK,
                "primary_container_id": primary_container_id,
            },
        )
        return TargetHandle(
            provider=self.name,
            target_id=manifest.id,
            network_name=BENCH_TARGET_NETWORK,
            target_alias=target_alias,
            metadata={
                "project_name": project_name,
                "source_dir": str(source_dir),
                "primary_container_id": primary_container_id,
            },
        )

    def healthcheck(self, handle: TargetHandle, manifest: Manifest, recorder: RunRecorder) -> HealthStatus:
        import time
        import requests as _requests

        checks = manifest.raw.get("target", {}).get("health", [])
        timeout = manifest.raw.get("target", {}).get("startup_timeout_seconds", 120)
        deadline = time.monotonic() + timeout
        poll_interval = 5

        last_error: str | None = None
        while time.monotonic() < deadline:
            all_ok = True
            for check in checks:
                ok, err = _run_health_check(check)
                if not ok:
                    all_ok = False
                    last_error = err
                    break
            if all_ok:
                recorder.event("target_healthy", {"checks": checks})
                return HealthStatus(ready=True, checks=checks)
            time.sleep(poll_interval)

        recorder.event("target_unhealthy", {"checks": checks, "last_error": last_error})
        return HealthStatus(ready=False, checks=checks, message=f"Target not healthy after {timeout}s: {last_error}")

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
            # bench_target is owned by the companion docker-compose; only bring
            # down the target containers, not the shared network.
            run_command(["docker", "compose", "-p", str(project_name), "down", "--remove-orphans"], recorder, cwd=source_dir, check=False)
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
    """Return a Docker Compose project name for the given run and manifest.

    The 63-character limit is derived from RFC 1035, which caps each DNS label
    at 63 octets.  For providers that do not set an explicit container_name in
    their compose files (e.g. VulHub), Docker Compose generates container names
    as ``{project}_{service}_1``.  Those container names are registered in
    Docker's internal DNS and must therefore be valid DNS labels.  The project
    name is the dominant component, so capping it at 63 characters ensures that
    even a short service name and replica suffix fit within the label limit.

    When the slug derived from the manifest ID exceeds the available space, it
    is truncated from the left rather than the right.  This preserves the vm
    identifier at the end of the slug (e.g. ``vm0``, ``vm10``), which is the
    most meaningful part for distinguishing containers within a category.
    """
    slug = "".join(ch if ch.isalnum() else "_" for ch in manifest_id.lower()).strip("_")
    prefix = f"bench_{run_id}_".lower()
    available = 63 - len(prefix)
    if len(slug) > available:
        slug = slug[-available:].lstrip("_")
    return f"{prefix}{slug}"


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


def _attach_compose_to_network(
    project_name: str,
    network_name: str,
    target_alias: str,
    manifest: Manifest,
    recorder: RunRecorder,
) -> str | None:
    """Connect all containers in a compose project to the bench network.

    The primary container (the one exposing the first manifest port) receives
    the target_alias so agent containers can resolve it by name. Returns the
    primary container ID, or None if no containers were found.
    """
    # Get all container IDs for this project
    result = subprocess.run(
        ["docker", "ps", "--filter", f"label=com.docker.compose.project={project_name}", "-q"],
        capture_output=True, text=True,
    )
    container_ids = [c.strip() for c in result.stdout.splitlines() if c.strip()]
    if not container_ids:
        return None

    # Identify the primary container: the one that has the first manifest port bound.
    # Fall back to the first container if no port match is found.
    primary_ports = manifest.raw.get("network", {}).get("exposed_ports", [])
    primary_port = primary_ports[0].split("/")[0] if primary_ports else None
    primary_id = _find_primary_container(container_ids, primary_port) or container_ids[0]

    # Connect all containers; primary gets the target alias.
    for cid in container_ids:
        args = ["docker", "network", "connect"]
        if cid == primary_id:
            args += ["--alias", target_alias]
        args += [network_name, cid]
        # Ignore errors — container may already be on the network.
        subprocess.run(args, capture_output=True)

    recorder.command(
        f"docker network connect (attach {len(container_ids)} containers to {network_name})",
        return_code=0,
    )
    return primary_id


def _find_primary_container(container_ids: list[str], port: str | None) -> str | None:
    """Return the container ID that has the given port published, or None."""
    if not port:
        return None
    result = subprocess.run(
        ["docker", "ps", "--filter", f"publish={port}", "-q"],
        capture_output=True, text=True,
    )
    published = {c.strip() for c in result.stdout.splitlines() if c.strip()}
    for cid in container_ids:
        if cid in published:
            return cid
    return None


def _run_health_check(check: dict[str, Any]) -> tuple[bool, str | None]:
    """Execute a single health check. Returns (ok, error_message)."""
    import socket
    import requests as _requests

    check_type = check.get("type", "tcp")
    try:
        if check_type == "http":
            # Replace the "target" alias with 127.0.0.1 — the orchestrator is on the
            # host and reaches containers through the bound ports, not the bench network.
            url = check.get("url", "").replace("//target:", "//127.0.0.1:")
            expect = check.get("expect_status", [200, 302, 401, 403])
            resp = _requests.get(url, timeout=5, allow_redirects=False)
            if resp.status_code in expect:
                return True, None
            return False, f"HTTP {resp.status_code} not in {expect} for {url}"

        elif check_type == "tcp":
            host = check.get("host", "127.0.0.1")
            if host == "target":
                host = "127.0.0.1"
            port = int(check.get("port", 80))
            with socket.create_connection((host, port), timeout=5):
                pass
            return True, None

    except Exception as exc:
        return False, str(exc)

    return False, f"unknown health check type: {check_type}"

