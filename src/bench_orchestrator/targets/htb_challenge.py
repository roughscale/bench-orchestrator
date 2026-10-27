from __future__ import annotations

import base64
import json
import os
import time
from typing import Any

import requests
import websocket

from bench_orchestrator.evidence import RunRecorder
from bench_orchestrator.models import HealthStatus, Manifest, RunContext, TargetHandle
from bench_orchestrator.targets.base import TargetProvider
from bench_orchestrator.targets.htb import _api_headers, _run_health_check, _vpn_interface_ip

_API_BASE = "https://labs.hackthebox.com/api/v4"
# Not under /api/v4 - this is HTB's Laravel Echo broadcasting-auth route,
# confirmed live by inspecting the web app's own traffic while starting a
# challenge container (no plain REST way to discover it otherwise - see
# module docstring below).
_BROADCAST_AUTH_URL = "https://labs.hackthebox.com/broadcasting/auth"
_PUSHER_WS_URL = "wss://ws.prod.htb.systems/app/239b8f4dc420f11e3fae?protocol=7&client=js&version=8.6.0&flash=false"


class HtbChallengeTargetProvider(TargetProvider):
    """Provisions an HTB *Challenge* container instance (play_methods:
    ["container"], e.g. "Diagnostic") via the Labs v4 API.

    File-based challenges (play_methods: ["download"]) are handled by
    StaticHostTargetProvider instead - this provider is only for challenges
    that spin up a live, reachable instance the same way a Machine does.

    Unlike Machines, HTB has no REST endpoint to poll a container's
    assigned address - confirmed live: the web UI itself learns it from a
    push over a private Pusher websocket channel (`private-{id}`, event
    `flock-container-start-event`), not from any `GET .../active`-style
    call. So start() reproduces that exact flow: open the same websocket,
    authorize the channel via HTB's own `/broadcasting/auth`, call
    `container/start`, then wait for the matching "ready" push carrying
    hostname/port.

    Channel name note: HTB previously used `private-user-{id}-containers`
    (confirmed live 2026-09) but has since renamed it to plain `private-{id}`
    (re-confirmed live 2026-10-26, by re-inspecting the web app's traffic
    after this provider started getting 403s from `/broadcasting/auth` on
    the old name - the old channel no longer exists server-side at all, so
    there was nothing to authorize).

    Activates when target.challenge_id or target.challenge_name is set in
    the manifest, and needs HTB_API_KEY - mirroring HtbTargetProvider's
    machine_id/machine_name contract for Machines.
    """

    name = "htb_challenge"

    def __init__(self) -> None:
        self._api_key: str | None = None
        self._challenge_id: int | None = None
        self._spawned_by_us = False
        self._leave_running = False

    def prepare(self, manifest: Manifest, context: RunContext, recorder: RunRecorder) -> None:
        target = manifest.raw.get("target", {})
        challenge_id = target.get("challenge_id")
        challenge_name = target.get("challenge_name") or manifest.raw.get("benchmark", {}).get("challenge_name")
        if challenge_id is None and not challenge_name:
            raise RuntimeError(
                "htb_challenge provider requires target.challenge_id, target.challenge_name, "
                "or benchmark.challenge_name in the manifest"
            )
        self._leave_running = bool(target.get("leave_running", False))
        if context.dry_run:
            recorder.event("target_prepared", {"provider": self.name, "dry_run": True})
            return

        api_key = os.environ.get("HTB_API_KEY")
        if not api_key:
            raise RuntimeError("HTB_API_KEY must be set to provision an HTB challenge container")
        self._api_key = api_key
        self._challenge_id = (
            int(challenge_id) if challenge_id is not None else _resolve_challenge_id(api_key, str(challenge_name))
        )
        recorder.event("target_prepared", {"provider": self.name, "challenge_id": self._challenge_id})

    def start(self, manifest: Manifest, context: RunContext, recorder: RunRecorder) -> TargetHandle:
        target = manifest.raw.get("target", {})
        # Same reasoning as HtbTargetProvider: the container is only
        # reachable through the host's VPN tunnel, so the agent needs the
        # host's own network namespace rather than a Docker bridge network.
        vpn_interface = target.get("vpn_interface", "tun0")
        attacker_ip = _vpn_interface_ip(vpn_interface)
        metadata: dict[str, Any] = {**target, "attacker_ip": attacker_ip, "challenge_id": self._challenge_id}
        # Some HTB challenges are play_methods: ["download", "container"] -
        # the agent needs both the downloaded source (to work out the
        # attack) and a live instance (to actually run it against the real
        # flag). Mirrors StaticHostTargetProvider's challenge_dir so
        # cai_agent.py's existing mount logic picks it up unchanged.
        if manifest.source_dir:
            metadata["challenge_dir"] = str(manifest.source_dir)

        if context.dry_run:
            recorder.event("target_started", {"provider": self.name, "dry_run": True})
            return TargetHandle(provider=self.name, target_id=manifest.id, network_mode="host", metadata=metadata)

        recorder.event("target_spawning", {"provider": self.name, "challenge_id": self._challenge_id})
        # Once container/start succeeds, anything that stops this from
        # returning a handle (a ready-event timeout, a Ctrl+C mid-wait) has
        # to stop its own container before propagating - the runner only
        # calls stop() when start() returned a handle. See HtbTargetProvider
        # for the same pattern on the Machines side.
        try:
            timeout = int(target.get("spawn_timeout_seconds", 180))
            host, port = _start_and_wait_for_ready(self._api_key, self._challenge_id, timeout)
            self._spawned_by_us = True
        except BaseException:
            try:
                _stop_container(self._api_key, self._challenge_id)
                recorder.event("target_spawn_aborted", {"provider": self.name, "challenge_id": self._challenge_id})
            except Exception as exc:
                recorder.event("teardown_failed", {"provider": self.name, "error": str(exc)})
            raise

        metadata["challenge_host"] = host
        metadata["challenge_port"] = port
        endpoint = f"{host}:{port}"
        recorder.event(
            "target_started",
            {"provider": self.name, "challenge_id": self._challenge_id, "endpoint": endpoint},
        )
        return TargetHandle(
            provider=self.name, target_id=manifest.id, endpoint=endpoint, network_mode="host", metadata=metadata
        )

    def healthcheck(self, handle: TargetHandle, manifest: Manifest, recorder: RunRecorder) -> HealthStatus:
        # Unlike Machines, the port isn't known ahead of time from the
        # manifest (it's assigned fresh on every spawn) - default to
        # checking the host:port the ready-event itself reported, unless
        # the manifest explicitly overrides what to check.
        target = manifest.raw.get("target", {})
        if not handle.endpoint:
            return HealthStatus(ready=False, checks=[])

        explicit_checks = target.get("health")
        if explicit_checks:
            checks = [{**check, "host": handle.metadata.get("challenge_host")} for check in explicit_checks]
        else:
            host = handle.metadata.get("challenge_host")
            port = handle.metadata.get("challenge_port")
            checks = [{"type": "tcp", "host": host, "port": port}] if host and port else []
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
            _stop_container(self._api_key, self._challenge_id)
            recorder.event("teardown_completed", {"provider": self.name, "challenge_id": self._challenge_id})
        except Exception as exc:
            recorder.event("teardown_failed", {"provider": self.name, "error": str(exc)})


# ------------------------------------------------------------------
# HTB Labs API - undocumented, reverse-engineered (see htb.py's own note on
# the Machines side of this API; same caveats apply). Challenge name
# resolution reuses the v4 keyword-search endpoint the web app's challenge
# list/search box calls, matched on an exact case-insensitive name for the
# same reason as _resolve_machine_id: a fuzzy first-hit risks the wrong
# challenge.
# ------------------------------------------------------------------


def _resolve_challenge_id(api_key: str, name: str) -> int:
    resp = requests.get(
        f"{_API_BASE}/challenges", params={"keyword": name, "per_page": 15},
        headers=_api_headers(api_key), timeout=15,
    )
    resp.raise_for_status()
    candidates = resp.json().get("data", [])
    matches = [c for c in candidates if str(c.get("name", "")).lower() == name.lower()]
    if not matches:
        found = [c.get("name") for c in candidates]
        raise RuntimeError(
            f"HTB challenge '{name}' not found by exact name (keyword search returned: {found or 'nothing'})"
        )
    if len(matches) > 1:
        raise RuntimeError(f"HTB challenge '{name}' matched multiple challenges: {[m.get('id') for m in matches]}")
    return int(matches[0]["id"])


def _decode_jwt_user_id(token: str) -> str:
    """Extract the `sub` claim from HTB_API_KEY, which is a JWT.

    The Pusher channel a running container is announced on is scoped
    per-account (`private-user-{id}-containers`), and there's no REST
    endpoint that just hands back "who am I" - the web app gets its own id
    the same way, by reading its own auth token.
    """
    try:
        payload_b64 = token.split(".")[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        return str(payload["sub"])
    except Exception as exc:
        raise RuntimeError(f"could not read a user id out of HTB_API_KEY (expected a JWT): {exc}") from exc


def _stop_container(api_key: str, challenge_id: int) -> None:
    resp = requests.post(
        f"{_API_BASE}/container/stop", json={"containerable_id": challenge_id},
        headers=_api_headers(api_key), timeout=30,
    )
    # A 404 here means it's already stopped/expired (HTB: "No results for
    # this container") - not worth failing teardown over.
    if not resp.ok and resp.status_code != 404:
        raise RuntimeError(f"HTB container/stop failed for challenge_id={challenge_id}: {resp.status_code} {resp.text.strip()}")


def _start_and_wait_for_ready(api_key: str, challenge_id: int, timeout_s: int) -> tuple[str, int]:
    """Start the container and block until HTB's Pusher push reports it
    ready, returning (host, port).

    Order matters: the websocket must be connected and subscribed *before*
    calling container/start, or the ready event (which can arrive within a
    couple of seconds) could fire before we're listening for it.
    """
    user_id = _decode_jwt_user_id(api_key)
    channel = f"private-{user_id}"

    ws = websocket.create_connection(_PUSHER_WS_URL, timeout=15)
    try:
        established = json.loads(ws.recv())
        if established.get("event") != "pusher:connection_established":
            raise RuntimeError(f"unexpected first Pusher frame: {established}")
        socket_id = json.loads(established["data"])["socket_id"]

        auth_resp = requests.post(
            _BROADCAST_AUTH_URL,
            data={"socket_id": socket_id, "channel_name": channel},
            headers=_api_headers(api_key),
            timeout=15,
        )
        auth_resp.raise_for_status()
        auth = auth_resp.json()["auth"]
        ws.send(json.dumps({"event": "pusher:subscribe", "data": {"channel": channel, "auth": auth}}))

        start_resp = requests.post(
            f"{_API_BASE}/container/start", json={"containerable_id": challenge_id},
            headers=_api_headers(api_key), timeout=30,
        )
        if not start_resp.ok:
            raise RuntimeError(
                f"HTB container/start failed for challenge_id={challenge_id}: "
                f"{start_resp.status_code} {start_resp.text.strip()}"
            )

        deadline = time.monotonic() + timeout_s
        last_seen: dict[str, Any] | None = None
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(
                    f"timed out after {timeout_s}s waiting for HTB challenge_id={challenge_id} "
                    f"container to become ready (last event seen: {last_seen})"
                )
            ws.settimeout(remaining)
            try:
                raw = ws.recv()
            except Exception as exc:
                raise RuntimeError(
                    f"Pusher websocket closed/errored while waiting for challenge_id={challenge_id}: {exc}"
                ) from exc
            frame = json.loads(raw)
            if frame.get("channel") != channel:
                continue
            data = frame.get("data")
            if isinstance(data, str):
                data = json.loads(data)
            if not isinstance(data, dict) or data.get("entity_id") != challenge_id:
                continue
            last_seen = data
            status = data.get("status")
            if status == "ready" and data.get("hostname"):
                port = data.get("port") or next(iter(data.get("ports") or []), None)
                if not port:
                    raise RuntimeError(f"HTB container ready event had no port: {data}")
                return str(data["hostname"]), int(port)
            if status == "failed":
                raise RuntimeError(f"HTB reported the container failed to start: {data}")
    finally:
        ws.close()
