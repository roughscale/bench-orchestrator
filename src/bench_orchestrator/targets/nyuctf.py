from __future__ import annotations

from pathlib import Path

from bench_orchestrator.evidence import RunRecorder
from bench_orchestrator.models import HealthStatus, Manifest, RunContext, TargetHandle
from bench_orchestrator.targets.base import TargetProvider
from bench_orchestrator.targets.vulhub import (
    COMPOSE_FILENAMES,
    _attach_compose_to_network,
    _run_health_check,
    docker_project_name,
    run_command,
)

CTFNET = "ctfnet"


class NyuCtfTargetProvider(TargetProvider):
    """Target provider for NYU CTF Bench challenges.

    Dockerised challenges are managed via docker-compose, following the same
    pattern as VulhubTargetProvider.  Static file challenges (no compose)
    return immediately — there is no target to start.

    NYU CTF Bench compose files declare an external ``ctfnet`` network.
    The provider creates this network before compose-up and attaches
    containers to the bench run network with the appropriate alias.
    """

    name = "nyuctf"

    def prepare(self, manifest: Manifest, context: RunContext, recorder: RunRecorder) -> None:
        source_dir = _require_source_dir(manifest)
        requires_compose = manifest.raw.get("target", {}).get("requires_compose", False)
        if requires_compose:
            if not any((source_dir / name).exists() for name in COMPOSE_FILENAMES):
                raise FileNotFoundError(f"no compose file found in {source_dir}")
        recorder.event("target_prepared", {"provider": self.name, "source_dir": str(source_dir)})

    def start(self, manifest: Manifest, context: RunContext, recorder: RunRecorder) -> TargetHandle:
        source_dir = _require_source_dir(manifest)
        requires_compose = manifest.raw.get("target", {}).get("requires_compose", False)

        if not requires_compose:
            recorder.event("target_started", {"provider": self.name, "static": True})
            return TargetHandle(
                provider=self.name,
                target_id=manifest.id,
                metadata={"source_dir": str(source_dir), "static": True},
            )

        project_name = docker_project_name(context.run_id, manifest.id)
        target_alias = manifest.raw.get("network", {}).get("target_alias", "target")
        network_name = context.target_network or f"bench_run_{context.run_id}"
        network_owned = context.target_network is None

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
                metadata={
                    "project_name": project_name,
                    "source_dir": str(source_dir),
                    "network_owned": network_owned,
                },
            )

        try:
            # NYU CTF Bench compose files require an external "ctfnet" network.
            run_command(["docker", "network", "create", CTFNET], recorder, check=False)

            if network_owned:
                run_command(["docker", "network", "create", network_name], recorder, check=False)

            run_command(
                ["docker", "compose", "-p", project_name, "up", "-d", "--remove-orphans"],
                recorder,
                cwd=source_dir,
            )

            primary_container_id = _attach_compose_to_network(
                project_name, network_name, target_alias, manifest, recorder
            )
        except Exception:
            run_command(
                ["docker", "compose", "-p", project_name, "down", "--remove-orphans"],
                recorder,
                cwd=source_dir,
                check=False,
            )
            if network_owned:
                run_command(["docker", "network", "rm", network_name], recorder, check=False)
            raise

        recorder.event(
            "target_started",
            {
                "project_name": project_name,
                "network_name": network_name,
                "network_owned": network_owned,
                "primary_container_id": primary_container_id,
            },
        )
        return TargetHandle(
            provider=self.name,
            target_id=manifest.id,
            network_name=network_name,
            target_alias=target_alias,
            metadata={
                "project_name": project_name,
                "source_dir": str(source_dir),
                "primary_container_id": primary_container_id,
                "network_owned": network_owned,
            },
        )

    def healthcheck(self, handle: TargetHandle, manifest: Manifest, recorder: RunRecorder) -> HealthStatus:
        import time

        if handle.metadata.get("static"):
            recorder.event("target_healthy", {"static": True})
            return HealthStatus(ready=True, message="static challenge — no target to check")

        checks = manifest.raw.get("target", {}).get("health", [])
        if not checks:
            recorder.event("target_healthy", {"checks": []})
            return HealthStatus(ready=True, message="no health checks configured")

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
        if handle.metadata.get("static"):
            return
        source_dir = Path(handle.metadata.get("source_dir", ""))
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
        if handle.metadata.get("static"):
            recorder.event("teardown_completed", {"provider": self.name, "static": True})
            return
        source_dir = Path(handle.metadata.get("source_dir", ""))
        project_name = handle.metadata.get("project_name")
        if project_name and not recorder.context.dry_run:
            run_command(
                ["docker", "compose", "-p", str(project_name), "down", "--remove-orphans"],
                recorder,
                cwd=source_dir,
                check=False,
            )
            if handle.metadata.get("network_owned") and handle.network_name:
                run_command(["docker", "network", "rm", handle.network_name], recorder, check=False)
            # Do not remove ctfnet — it may be shared across runs.
        recorder.event("teardown_completed", {"provider": self.name, "target_id": handle.target_id})


def _require_source_dir(manifest: Manifest) -> Path:
    source_dir = manifest.source_dir
    if source_dir is None:
        raise ValueError(f"manifest {manifest.id} is missing source_dir")
    return source_dir
