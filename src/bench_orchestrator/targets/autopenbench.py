from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from bench_orchestrator.evidence import RunRecorder
from bench_orchestrator.models import HealthStatus, Manifest, RunContext, TargetHandle
from bench_orchestrator.targets.base import TargetProvider
from bench_orchestrator.targets.vulhub import (
    _attach_compose_to_network,
    docker_project_name,
    run_command,
)


class AutoPenBenchTargetProvider(TargetProvider):
    """Start individual AutoPenBench targets from their category compose files.

    Expected manifest fields:
        source_dir: absolute path to the AutoPenBench machines directory
                    (benchmark/machines/ inside the checkout)
        autopenbench:
            compose_file: relative path to the category compose file
                          (e.g. "in-vitro/access_control/docker-compose.yml")
            service:      compose service name (e.g. "in-vitro_access_control_vm0")
        network:
            target_alias: alias assigned on bench_target (default: "target")
        target:
            startup_timeout_seconds: how long to wait for health (default: 60)
            health:
              - type: container_running
                container: <service_name>
    """

    name = "autopenbench"

    def prepare(self, manifest: Manifest, context: RunContext, recorder: RunRecorder) -> None:
        apb = _require_apb(manifest)
        machines_dir = _require_machines_dir(manifest)
        compose_path = machines_dir / apb["compose_file"]
        if not compose_path.exists():
            raise FileNotFoundError(f"compose file not found: {compose_path}")
        services = apb.get("services") or [apb["service"]]
        recorder.event("target_prepared", {"provider": self.name, "services": services})

    def start(self, manifest: Manifest, context: RunContext, recorder: RunRecorder) -> TargetHandle:
        apb = _require_apb(manifest)
        machines_dir = _require_machines_dir(manifest)
        compose_file = machines_dir / apb["compose_file"]
        # Support either a single `service` name or a `services` list (e.g. vm5
        # which requires two victim containers for ARP spoofing).
        services = apb.get("services") or [apb["service"]]
        project = docker_project_name(context.run_id, manifest.id)
        # AutoPenBench compose files define a network called net-main_network.
        # Docker Compose prefixes it with the project name, producing this name.
        # This is the network that target containers treat as eth0 — the interface
        # their iptables rules accept traffic on.  Kali must be attached to it for
        # any traffic to reach network_security targets.
        project_net = f"{project}_net-main_network"
        target_alias = manifest.raw.get("network", {}).get("target_alias", "target")
        kali_ip = manifest.raw.get("network", {}).get("kali_ip") or None

        network_name = context.target_network or f"bench_run_{context.run_id}"
        network_owned = context.target_network is None

        if context.dry_run:
            recorder.event(
                "target_started",
                {"dry_run": True, "project_name": project, "network_name": network_name},
            )
            return TargetHandle(
                provider=self.name,
                target_id=manifest.id,
                network_name=network_name,
                target_alias=target_alias,
                metadata={
                    "project_name": project,
                    "machines_dir": str(machines_dir),
                    "compose_file": str(compose_file),
                    "services": services,
                    "kali_project_network": project_net,
                    "network_owned": network_owned,
                },
            )

        kali_connected = False
        try:
            if network_owned:
                run_command(["docker", "network", "create", network_name], recorder, check=False)

            # --project-directory ensures relative volume/build paths inside the
            # category compose files resolve from the machines root, which is the
            # convention AutoPenBench uses for its compose files.
            run_command(
                [
                    "docker", "compose",
                    "--project-directory", str(machines_dir),
                    "-f", str(compose_file),
                    "-p", project,
                    "up", "-d", *services,
                ],
                recorder,
                cwd=machines_dir,
            )
            primary_container_id = _attach_compose_to_network(
                project, network_name, target_alias, manifest, recorder
            )

            # Connect Kali to the project's net-main_network so that traffic
            # arrives on the target's eth0 interface.  AutoPenBench iptables
            # rules only accept on eth0; traffic arriving via bench_target (eth1)
            # is silently dropped.  This also populates target_net and attacker_ip
            # with the correct 10.200.x.x values rather than bench_target values.
            _connect_kali_to_network(project_net, recorder, kali_ip=kali_ip)
            kali_connected = True

        except Exception:
            if kali_connected:
                _disconnect_kali_from_network(project_net, recorder)
            run_command(
                [
                    "docker", "compose",
                    "--project-directory", str(machines_dir),
                    "-f", str(compose_file),
                    "-p", project,
                    "down", "--remove-orphans",
                ],
                recorder,
                cwd=machines_dir,
                check=False,
            )
            if network_owned:
                run_command(["docker", "network", "rm", network_name], recorder, check=False)
            raise

        target_ip, target_net = _inspect_network(primary_container_id, project_net)
        attacker_ip = _inspect_attacker_ip(project_net)

        recorder.event(
            "target_started",
            {
                "project_name": project,
                "network_name": network_name,
                "network_owned": network_owned,
                "primary_container_id": primary_container_id,
                "target_ip": target_ip,
                "target_net": target_net,
                "attacker_ip": attacker_ip,
            },
        )
        return TargetHandle(
            provider=self.name,
            target_id=manifest.id,
            network_name=network_name,
            target_alias=target_alias,
            metadata={
                "project_name": project,
                "machines_dir": str(machines_dir),
                "compose_file": str(compose_file),
                "services": services,
                "primary_container_id": primary_container_id,
                "target_ip": target_ip,
                "target_net": target_net,
                "attacker_ip": attacker_ip,
                "kali_project_network": project_net,
                "network_owned": network_owned,
            },
        )

    def healthcheck(self, handle: TargetHandle, manifest: Manifest, recorder: RunRecorder) -> HealthStatus:
        import time

        checks = manifest.raw.get("target", {}).get("health", [])
        timeout = manifest.raw.get("target", {}).get("startup_timeout_seconds", 60)
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
        return HealthStatus(
            ready=False,
            checks=checks,
            message=f"Target not healthy after {timeout}s: {last_error}",
        )

    def collect_logs(self, handle: TargetHandle, manifest: Manifest, recorder: RunRecorder) -> None:
        machines_dir = handle.metadata.get("machines_dir", "")
        compose_file = handle.metadata.get("compose_file", "")
        project_name = handle.metadata.get("project_name")
        if not project_name or not compose_file:
            return
        output = recorder.target_log_dir / "docker-compose.log"
        if recorder.context.dry_run:
            output.write_text("dry-run: docker compose logs not collected\n", encoding="utf-8")
            return
        result = run_command(
            [
                "docker", "compose",
                "--project-directory", machines_dir,
                "-f", compose_file,
                "-p", project_name,
                "logs", "--no-color",
            ],
            recorder,
            cwd=Path(machines_dir),
            check=False,
        )
        output.write_text(result.stdout or "", encoding="utf-8")

    def stop(self, handle: TargetHandle, manifest: Manifest, recorder: RunRecorder) -> None:
        machines_dir = handle.metadata.get("machines_dir", "")
        compose_file = handle.metadata.get("compose_file", "")
        project_name = handle.metadata.get("project_name")
        kali_project_network = handle.metadata.get("kali_project_network")
        if not recorder.context.dry_run:
            # Disconnect Kali from the project network before compose down.
            # docker compose down removes the project network; if Kali is still
            # connected Docker refuses to delete it, leaving a dangling network.
            if kali_project_network:
                _disconnect_kali_from_network(kali_project_network, recorder)
            if project_name and compose_file:
                run_command(
                    [
                        "docker", "compose",
                        "--project-directory", machines_dir,
                        "-f", compose_file,
                        "-p", project_name,
                        "down", "--remove-orphans",
                    ],
                    recorder,
                    cwd=Path(machines_dir),
                    check=False,
                )
            if handle.metadata.get("network_owned") and handle.network_name:
                run_command(["docker", "network", "rm", handle.network_name], recorder, check=False)
        recorder.event("teardown_completed", {"provider": self.name, "target_id": handle.target_id})


def _require_apb(manifest: Manifest) -> dict[str, Any]:
    apb = manifest.raw.get("autopenbench")
    if not apb:
        raise ValueError(f"manifest {manifest.id} is missing 'autopenbench' section")
    return apb


def _require_machines_dir(manifest: Manifest) -> Path:
    source_dir = manifest.source_dir
    if source_dir is None:
        raise ValueError(f"manifest {manifest.id} is missing source_dir")
    return source_dir


def _inspect_attacker_ip(network_name: str) -> str | None:
    """Return the Kali attacker IP on the given network.

    Inspects all containers on the network and returns the IP of whichever one
    has 'kali' in its name (the shared attacker machine started by infra).
    Returns None if the network doesn't exist or Kali isn't connected yet.
    """
    result = subprocess.run(
        [
            "docker", "network", "inspect", network_name,
            "--format", "{{range $id, $c := .Containers}}{{$c.Name}} {{$c.IPv4Address}}\n{{end}}",
        ],
        capture_output=True, text=True,
    )
    for line in result.stdout.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and "kali" in parts[0].lower():
            # IPv4Address is in CIDR notation (e.g. "172.26.0.2/16")
            return parts[1].split("/")[0] or None
    return None


def _find_kali_container() -> str | None:
    """Return the container ID of the Kali attacker machine.

    Looks up the Kali container via the bench_attacker network, where Kali has a
    static IP and is always present when infrastructure is running.  Returns None
    if infrastructure is not up or no container with 'kali' in the name is found.
    """
    result = subprocess.run(
        [
            "docker", "network", "inspect", "bench_attacker",
            "--format", "{{range $id, $c := .Containers}}{{$c.Name}} {{$id}}\n{{end}}",
        ],
        capture_output=True, text=True,
    )
    for line in result.stdout.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and "kali" in parts[0].lower():
            return parts[1]
    return None


def _connect_kali_to_network(network_name: str, recorder: RunRecorder, kali_ip: str | None = None) -> None:
    """Connect the Kali container to the given Docker network.

    If kali_ip is provided, Kali is assigned that static IP on the network.
    This is required for challenges whose traffic generators hardcode the
    attacker address (e.g. network_security/vm4 duster.sh TARGET="10.200.0.5").

    Raises RuntimeError if Kali cannot be found (infrastructure not running) or
    if the network connect command fails.
    """
    kali_id = _find_kali_container()
    if not kali_id:
        raise RuntimeError(
            "Kali container not found on bench_attacker — is infrastructure running? "
            "Run 'docker compose up -d' from the repo root before starting a benchmark."
        )
    cmd = ["docker", "network", "connect"]
    if kali_ip:
        cmd += ["--ip", kali_ip]
    cmd += [network_name, kali_id]
    result = subprocess.run(cmd, capture_output=True, text=True)
    recorder.command(
        f"docker network connect {network_name} {kali_id[:12]}",
        return_code=result.returncode,
        stderr=result.stderr,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"failed to connect Kali ({kali_id[:12]}) to {network_name}: {result.stderr.strip()}"
        )


def _disconnect_kali_from_network(network_name: str, recorder: RunRecorder) -> None:
    """Disconnect Kali from the given Docker network.

    Errors are logged but not raised — this runs in the teardown path and must
    not prevent subsequent cleanup steps from executing.
    """
    kali_id = _find_kali_container()
    if not kali_id:
        return
    result = subprocess.run(
        ["docker", "network", "disconnect", network_name, kali_id],
        capture_output=True, text=True,
    )
    recorder.command(
        f"docker network disconnect {network_name} {kali_id[:12]}",
        return_code=result.returncode,
        stderr=result.stderr,
    )


def _inspect_network(container_id: str | None, network_name: str) -> tuple[str | None, str | None]:
    """Return (container_ip, network_subnet) for the named network.

    Both values may be None if the container ID is unknown or the inspect fails.
    """
    if not container_id:
        return None, None

    # Container IP on the specific network
    ip_result = subprocess.run(
        [
            "docker", "inspect",
            "--format", f"{{{{index .NetworkSettings.Networks \"{network_name}\" \"IPAddress\"}}}}",
            container_id,
        ],
        capture_output=True, text=True,
    )
    target_ip = ip_result.stdout.strip() or None

    # Subnet of the network itself
    subnet_result = subprocess.run(
        [
            "docker", "network", "inspect",
            "--format", "{{range .IPAM.Config}}{{.Subnet}}{{end}}",
            network_name,
        ],
        capture_output=True, text=True,
    )
    target_net = subnet_result.stdout.strip() or None

    return target_ip, target_net


def _run_health_check(check: dict[str, Any]) -> tuple[bool, str | None]:
    """Execute one health check. Returns (ok, error_message)."""
    import socket

    check_type = check.get("type", "container_running")
    try:
        if check_type == "container_running":
            container = check.get("container", "")
            result = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Status}}", container],
                capture_output=True,
                text=True,
            )
            status = result.stdout.strip()
            if status == "running":
                return True, None
            return False, f"container '{container}' status: {status or 'not found'}"

        elif check_type == "tcp":
            host = check.get("host", "127.0.0.1")
            if host == "target":
                host = "127.0.0.1"
            port = int(check.get("port", 22))
            with socket.create_connection((host, port), timeout=5):
                pass
            return True, None

    except Exception as exc:
        return False, str(exc)

    return False, f"unknown health check type: {check_type}"
