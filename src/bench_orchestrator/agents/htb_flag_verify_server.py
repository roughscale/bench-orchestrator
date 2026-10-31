from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

import requests

from bench_orchestrator.models import Manifest, TargetHandle
from bench_orchestrator.targets.htb import _api_headers
from bench_orchestrator.targets.htb_challenge import _resolve_challenge_id

_CHALLENGE_OWN_URL = "https://labs.hackthebox.com/api/v4/challenge/own"
_MACHINE_OWN_URL = "https://labs.hackthebox.com/api/v5/machine/own"

VerifyFn = Callable[[str], tuple[bool, str]]

# A correct flag re-submitted for a challenge this account has *already
# owned* comes back as HTTP 400 with {"message": "Challenge already solved"}
# (confirmed live - status and body both verified against /challenge/own).
# HTB validates the flag before returning that, so it's positive evidence
# the submitted flag is right and must count as correct - otherwise every
# challenge this benchmark account solved before is an unwinnable false
# negative regardless of how the agent performs. A genuinely wrong flag is
# also a 400 but carries "Incorrect flag", so it's the message, gated on the
# 400 status, that distinguishes the two.
_ALREADY_OWNED_RE = re.compile(r"already (solved|owned|completed|submitted)", re.IGNORECASE)


def _verify_challenge_flag(api_key: str, challenge_id: int, flag: str) -> tuple[bool, str]:
    resp = requests.post(
        _CHALLENGE_OWN_URL, json={"flag": flag, "challenge_id": challenge_id},
        headers=_api_headers(api_key), timeout=15,
    )
    if resp.status_code == 200:
        return True, (resp.json() or {}).get("message") or "Correct!"
    if resp.status_code in (400, 403, 422):
        message = (resp.json() or {}).get("message") or "Incorrect flag."
        # A 400 "Challenge already solved" means the flag was correct for an
        # already-owned challenge - count it (see _ALREADY_OWNED_RE above).
        # Only a 400 carries this; 403/422 stay plain rejections.
        if resp.status_code == 400 and _ALREADY_OWNED_RE.search(message):
            return True, message
        # Wrong flag, or a malformed candidate (e.g. HTB's own 191-char
        # submission length limit, confirmed live) - either way, not
        # correct, not a real error worth surfacing as one.
        return False, message
    raise RuntimeError(f"HTB challenge/own returned an unexpected status: {resp.status_code} {resp.text.strip()}")


def _verify_machine_flag(api_key: str, machine_id: int, flag: str, recorder=None) -> tuple[bool, str]:
    resp = requests.post(
        _MACHINE_OWN_URL, json={"id": machine_id, "flag": flag},
        headers=_api_headers(api_key), timeout=15,
    )
    if recorder is not None:
        recorder.event("flag_verify_response", {
            "kind": "machine", "machine_id": machine_id, "flag": flag,
            "status_code": resp.status_code, "body": resp.text,
        })
    if resp.status_code == 200:
        return True, (resp.json() or {}).get("message") or "Correct!"
    if resp.status_code == 400:
        return False, (resp.json() or {}).get("message") or "Incorrect flag."
    # Includes the "no active instance" 500 confirmed live - a setup
    # problem, not a real pass/fail verdict.
    raise RuntimeError(f"HTB machine/own returned an unexpected status: {resp.status_code} {resp.text.strip()}")


class _VerifyHandler(BaseHTTPRequestHandler):
    server: "_VerifyHTTPServer"

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's naming convention
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
            flag = str(body["flag"])
        except Exception as exc:
            self._respond({"correct": False, "message": f"bad request: {exc}"})
            return
        try:
            correct, message = self.server.verify_fn(flag)
        except Exception as exc:
            # Surfaced to the agent as a normal (non-fatal) tool response -
            # submit_flag_tool.py already treats this shape as "couldn't
            # verify, try again" rather than a crash.
            correct, message = False, f"verification error: {exc}"
        self._respond({"correct": correct, "message": message})

    def _respond(self, payload: dict[str, Any]) -> None:
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass  # the default stderr access log isn't useful for this


class _VerifyHTTPServer(ThreadingHTTPServer):
    def __init__(self, verify_fn: VerifyFn) -> None:
        # 0.0.0.0, not 127.0.0.1: the container reaches this via
        # host.docker.internal (added to its /etc/hosts by
        # --add-host=host.docker.internal:host-gateway in
        # _build_docker_cmd), which resolves to a real routable host
        # address, not loopback - a loopback-only bind would never see
        # that traffic arrive.
        super().__init__(("0.0.0.0", 0), _VerifyHandler)
        self.verify_fn = verify_fn


class FlagVerifyServer:
    """A short-lived local HTTP server so a cai container's submit_flag tool
    can get real HTB verification without cai needing to know anything
    about HTB - see cai's bench/submit_flag_tool.py (CHALLENGE_FLAG_VERIFY_URL).
    One instance per task run: started just before the container, stopped
    right after, regardless of outcome (see CaiAgentAdapter.run()).
    """

    def __init__(self, verify_fn: VerifyFn) -> None:
        self._httpd = _VerifyHTTPServer(verify_fn)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


def build_verify_server(manifest: Manifest, target: TargetHandle, api_key: str, recorder=None) -> FlagVerifyServer | None:
    """Resolve what this task should be verified against, if anything.

    /api/v4/challenge/own is keyed on the challenge's own persistent id,
    not anything tied to a spawned container - it works identically for a
    file-based (static_host) challenge as it does for a live one like
    Diagnostic. So this checks target.metadata first (already resolved by
    HtbChallengeTargetProvider/HtbTargetProvider), then falls back to
    resolving a challenge_id by name from the manifest's own
    benchmark.challenge_name - covering every static_host HTB challenge
    too, not just the container-based one.
    """
    challenge_id = target.metadata.get("challenge_id")
    if challenge_id is None:
        benchmark = manifest.raw.get("benchmark", {})
        if benchmark.get("platform") == "htb" and benchmark.get("challenge_name"):
            challenge_id = _resolve_challenge_id(api_key, str(benchmark["challenge_name"]))
    if challenge_id is not None:
        return FlagVerifyServer(lambda flag: _verify_challenge_flag(api_key, int(challenge_id), flag))

    machine_id = target.metadata.get("machine_id")
    if machine_id is not None:
        return FlagVerifyServer(lambda flag: _verify_machine_flag(api_key, int(machine_id), flag, recorder))

    return None
