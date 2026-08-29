from __future__ import annotations

import os
import re
import subprocess
import time
from typing import Any

import requests

from bench_orchestrator.evidence import RunRecorder
from bench_orchestrator.models import HealthStatus, Manifest, RunContext, TargetHandle
from bench_orchestrator.targets.base import TargetProvider

_API_BASE = "https://labs.hackthebox.com/api/v4"


def _vpn_interface_ip(interface: str) -> str | None:
    """Return the host's IPv4 address on the given VPN interface, or None."""
    result = subprocess.run(
        ["ip", "-4", "-oneline", "addr", "show", interface],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return None
    match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", result.stdout)
    return match.group(1) if match else None


class HtbTargetProvider(TargetProvider):
    """Provisions an HTB machine via the Labs v4 API: spawn it, wait for an
    assigned IP, hand it to the agent, terminate it on teardown - the same
    spawn/play/stop lifecycle as clicking through the HTB web UI, so a run
    doesn't need a human to spawn/reset the box and paste in its IP first.

    Auto-provisioning activates when the manifest gives target.machine_id or
    target.machine_name, and needs HTB_API_KEY set. Without either, this
    falls back to the original unmanaged mode: target.host is used as-is (a
    machine spawned by hand) and the API is never called.
    """

    name = "htb"

    def __init__(self) -> None:
        self._api_key: str | None = None
        self._machine_id: int | None = None
        self._spawned_by_us = False
        self._leave_running = False

    def prepare(self, manifest: Manifest, context: RunContext, recorder: RunRecorder) -> None:
        target = manifest.raw.get("target", {})
        machine_id = target.get("machine_id")
        machine_name = target.get("machine_name")
        if machine_id is None and machine_name is None:
            recorder.event("target_prepared", {"provider": self.name, "mode": "unmanaged"})
            return

        self._leave_running = bool(target.get("leave_running", False))
        if context.dry_run:
            recorder.event("target_prepared", {"provider": self.name, "mode": "auto", "dry_run": True})
            return

        api_key = os.environ.get("HTB_API_KEY")
        if not api_key:
            raise RuntimeError(
                "HTB_API_KEY must be set to auto-provision an HTB machine "
                "(target.machine_id or target.machine_name is set in the manifest)"
            )
        self._api_key = api_key
        self._machine_id = int(machine_id) if machine_id is not None else _resolve_machine_id(api_key, str(machine_name))
        recorder.event("target_prepared", {"provider": self.name, "mode": "auto", "machine_id": self._machine_id})

    def start(self, manifest: Manifest, context: RunContext, recorder: RunRecorder) -> TargetHandle:
        target = manifest.raw.get("target", {})
        # HTB machines are reachable only through the host's VPN tunnel, not
        # via a Docker network we create - the agent container needs the
        # host's own network namespace (see TargetHandle.network_mode) to
        # both reach the target and be reachable back for callbacks.
        vpn_interface = target.get("vpn_interface", "tun0")
        attacker_ip = _vpn_interface_ip(vpn_interface)
        metadata = {**target, "attacker_ip": attacker_ip}

        if self._machine_id is None:
            endpoint = target.get("host")
            recorder.event("target_started", {"provider": self.name, "mode": "unmanaged", "endpoint": endpoint})
            return TargetHandle(provider=self.name, target_id=manifest.id, endpoint=endpoint,
                                 network_mode="host", metadata=metadata)

        metadata["machine_id"] = self._machine_id
        if context.dry_run:
            recorder.event("target_started", {"provider": self.name, "mode": "auto", "dry_run": True})
            return TargetHandle(provider=self.name, target_id=manifest.id, network_mode="host", metadata=metadata)

        active = _get_active_machine(self._api_key)
        if active and active.get("id") not in (None, self._machine_id):
            if not target.get("auto_terminate_other_active", False):
                raise RuntimeError(
                    f"a different HTB machine is already active (id={active['id']}, "
                    f"name={active.get('name')}) - stop it manually first, or set "
                    "target.auto_terminate_other_active: true to replace it"
                )
            recorder.event("target_terminating_other_active", {"provider": self.name, "machine_id": active["id"]})
            _terminate_machine(self._api_key, active["id"])
            active = None

        if active and active.get("id") == self._machine_id and active.get("ip"):
            recorder.event("target_reused_active", {"provider": self.name, "machine_id": self._machine_id, "ip": active["ip"]})
        else:
            recorder.event("target_spawning", {"provider": self.name, "machine_id": self._machine_id})
            _spawn_machine(self._api_key, self._machine_id)
            self._spawned_by_us = True

        timeout = int(target.get("spawn_timeout_seconds", 300))
        endpoint = _wait_for_ip(self._api_key, self._machine_id, timeout)
        recorder.event("target_started", {"provider": self.name, "mode": "auto", "machine_id": self._machine_id, "endpoint": endpoint})

        return TargetHandle(provider=self.name, target_id=manifest.id, endpoint=endpoint,
                             network_mode="host", metadata=metadata)

    def healthcheck(self, handle: TargetHandle, manifest: Manifest, recorder: RunRecorder) -> HealthStatus:
        # Reachability, not a fresh box - the machine is already spawned
        # (auto-provisioned above, or by hand beforehand). This just confirms
        # the tunnel is up and the target is actually listening before
        # handing off to the agent. Host is always handle.endpoint (resolved
        # at start(), possibly just now from the API), never anything from
        # the manifest, since that endpoint is only known then.
        #
        # target.health lets a manifest override which checks run and how -
        # needed e.g. when target.ports includes a UDP-only service (SNMP on
        # UnderPass): a plain TCP connect to that port would just fail. When
        # absent, every port in target.ports gets a TCP check by default.
        target = manifest.raw.get("target", {})
        if not handle.endpoint:
            return HealthStatus(ready=False, checks=[])

        explicit_checks = target.get("health")
        if explicit_checks:
            checks = [{**check, "host": handle.endpoint} for check in explicit_checks]
        else:
            checks = [{"type": "tcp", "host": handle.endpoint, "port": port} for port in (target.get("ports") or [])]
        if not checks:
            return HealthStatus(ready=True, checks=[])
        timeout = target.get("startup_timeout_seconds", 60)
        deadline = time.monotonic() + timeout
        poll_interval = 5
        last_error: str | None = None
        while True:
            all_ok = True
            for check in checks:
                ok, err = _run_health_check(check)
                if not ok:
                    all_ok, last_error = False, err
                    break
            if all_ok:
                recorder.event("target_healthy", {"checks": checks})
                return HealthStatus(ready=True, checks=checks)
            if time.monotonic() >= deadline:
                break
            time.sleep(poll_interval)

        recorder.event("target_unhealthy", {"checks": checks, "last_error": last_error})
        return HealthStatus(ready=False, checks=checks, message=f"Target not healthy after {timeout}s: {last_error}")

    def collect_logs(self, handle: TargetHandle, manifest: Manifest, recorder: RunRecorder) -> None:
        recorder.event("target_logs_collected", {"provider": self.name, "status": "not_available"})

    def stop(self, handle: TargetHandle, manifest: Manifest, recorder: RunRecorder) -> None:
        if not self._spawned_by_us or self._leave_running:
            recorder.event("teardown_completed", {"provider": self.name, "status": "left_running_or_unmanaged"})
            return
        try:
            _terminate_machine(self._api_key, self._machine_id)
            recorder.event("teardown_completed", {"provider": self.name, "machine_id": self._machine_id})
        except Exception as exc:
            recorder.event("teardown_failed", {"provider": self.name, "error": str(exc)})


# ------------------------------------------------------------------
# HTB Labs API - undocumented, reverse-engineered from the web app's own
# traffic (no official spec covers the consumer Machines platform; HTB's
# only published API is the unrelated Enterprise product). machine/active
# and vm/spawn|terminate are v4, same family as cai's existing
# bench/orchestrator.py::get_htb_active_machine_ip. Name resolution is v5:
# v4's /machine/profile/{name} doesn't actually do name lookups despite its
# own docs (confirmed live - 404s even for machines that exist), so this
# uses the same keyword-search endpoint the web app's machine list/search
# box calls, matched on an exact case-insensitive name (a fuzzy first-hit
# would risk resolving e.g. "Cat" to the wrong machine - "Catch" also
# matches that keyword).
# ------------------------------------------------------------------

_API_BASE_V5 = "https://labs.hackthebox.com/api/v5"


def _api_headers(api_key: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
        # Cloudflare in front of labs.hackthebox.com bot-mitigates on the
        # default python-requests/x.y User-Agent (returns a fake 404, not a
        # proper block page - confirmed live). curl's default UA passes, so
        # use that rather than requests' own default.
        "User-Agent": "curl/8.5.0",
    }


def _resolve_machine_id(api_key: str, name: str) -> int:
    resp = requests.get(
        f"{_API_BASE_V5}/machines", params={"keyword": name, "per_page": 15},
        headers=_api_headers(api_key), timeout=15,
    )
    resp.raise_for_status()
    candidates = resp.json().get("data", [])
    matches = [m for m in candidates if str(m.get("name", "")).lower() == name.lower()]
    if not matches:
        found = [m.get("name") for m in candidates]
        raise RuntimeError(
            f"HTB machine '{name}' not found by exact name (keyword search returned: {found or 'nothing'})"
        )
    if len(matches) > 1:
        raise RuntimeError(f"HTB machine '{name}' matched multiple machines: {[m.get('id') for m in matches]}")
    return int(matches[0]["id"])


def _get_active_machine(api_key: str) -> dict[str, Any] | None:
    resp = requests.get(f"{_API_BASE}/machine/active", headers=_api_headers(api_key), timeout=15)
    resp.raise_for_status()
    return resp.json().get("info") or None


def _spawn_machine(api_key: str, machine_id: int) -> None:
    resp = requests.post(f"{_API_BASE}/vm/spawn", json={"machine_id": machine_id}, headers=_api_headers(api_key), timeout=30)
    if not resp.ok:
        raise RuntimeError(f"HTB vm/spawn failed for machine_id={machine_id}: {resp.status_code} {resp.text.strip()}")


def _terminate_machine(api_key: str, machine_id: int) -> None:
    resp = requests.post(f"{_API_BASE}/vm/terminate", json={"machine_id": machine_id}, headers=_api_headers(api_key), timeout=30)
    if not resp.ok:
        raise RuntimeError(f"HTB vm/terminate failed for machine_id={machine_id}: {resp.status_code} {resp.text.strip()}")


def _wait_for_ip(api_key: str, machine_id: int, timeout_s: int, poll_interval: int = 10) -> str:
    deadline = time.monotonic() + timeout_s
    last_seen: dict[str, Any] | None = None
    while True:
        active = _get_active_machine(api_key)
        if active:
            last_seen = active
            if active.get("id") == machine_id and active.get("ip"):
                return str(active["ip"])
        if time.monotonic() >= deadline:
            break
        time.sleep(poll_interval)
    raise RuntimeError(
        f"timed out after {timeout_s}s waiting for HTB machine_id={machine_id} to get an IP "
        f"(last machine/active: {last_seen})"
    )


def _run_health_check(check: dict[str, Any]) -> tuple[bool, str | None]:
    """Execute a single health check against the real target IP.

    Same shape as vulhub/autopenbench's health check, minus the "target"
    alias substitution - an HTB target is a real routable IP behind the VPN
    tunnel, not a Docker network alias.
    """
    import socket

    check_type = check.get("type", "tcp")
    try:
        if check_type == "http":
            url = check.get("url", "")
            expect = check.get("expect_status", [200, 302, 401, 403])
            resp = requests.get(url, timeout=5, allow_redirects=False, verify=False)
            if resp.status_code in expect:
                return True, None
            return False, f"HTTP {resp.status_code} not in {expect} for {url}"

        elif check_type == "tcp":
            host = check.get("host")
            port = int(check.get("port", 80))
            with socket.create_connection((host, port), timeout=5):
                pass
            return True, None

    except Exception as exc:
        return False, str(exc)

    return False, f"unknown health check type: {check_type}"
