"""HtbChallengeTargetProvider teardown behaviour - mirrors test_htb_provider.py
for Machines: a container we start must not be leaked when start() fails or
is interrupted after container/start succeeds but before start() returns a
handle (the runner only tears down when start() handed back a handle, so
start() has to clean up its own spawn)."""
import base64
import json
from pathlib import Path

import pytest

from bench_orchestrator.models import Manifest, RunContext
from bench_orchestrator.targets import htb_challenge


class _Recorder:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def event(self, phase: str, payload: dict | None = None) -> None:
        self.events.append((phase, payload or {}))


def _manifest() -> Manifest:
    return Manifest(raw={"id": "htb/challenges/diagnostic", "provider": "htb_challenge",
                          "target": {"challenge_name": "Diagnostic"}})


def _provider(monkeypatch):
    """An HtbChallengeTargetProvider with prepare() already done
    (challenge_id=360) and every outbound HTB call stubbed."""
    monkeypatch.setattr(htb_challenge, "_vpn_interface_ip", lambda _iface: "10.10.14.9")

    stopped: list[int] = []
    monkeypatch.setattr(htb_challenge, "_stop_container", lambda _key, cid: stopped.append(cid))

    provider = htb_challenge.HtbChallengeTargetProvider()
    provider._api_key = "key"
    provider._challenge_id = 360
    return provider, stopped


def test_spawn_then_wait_timeout_stops_the_container(monkeypatch) -> None:
    provider, stopped = _provider(monkeypatch)
    monkeypatch.setattr(
        htb_challenge, "_start_and_wait_for_ready",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("timed out waiting for ready event")),
    )
    ctx = RunContext.create(Path.cwd())

    with pytest.raises(RuntimeError, match="timed out"):
        provider.start(_manifest(), ctx, _Recorder())

    assert stopped == [360]


def test_spawn_then_keyboard_interrupt_stops_the_container(monkeypatch) -> None:
    provider, stopped = _provider(monkeypatch)
    monkeypatch.setattr(
        htb_challenge, "_start_and_wait_for_ready",
        lambda *_a, **_k: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    ctx = RunContext.create(Path.cwd())

    with pytest.raises(KeyboardInterrupt):
        provider.start(_manifest(), ctx, _Recorder())

    assert stopped == [360]


def test_successful_start_returns_handle_and_stops_nothing(monkeypatch) -> None:
    provider, stopped = _provider(monkeypatch)
    monkeypatch.setattr(htb_challenge, "_start_and_wait_for_ready", lambda *_a, **_k: ("154.57.164.82", 31392))
    ctx = RunContext.create(Path.cwd())

    handle = provider.start(_manifest(), ctx, _Recorder())

    assert handle.endpoint == "154.57.164.82:31392"
    assert handle.metadata["challenge_host"] == "154.57.164.82"
    assert handle.metadata["challenge_port"] == 31392
    assert stopped == []
    assert provider._spawned_by_us is True


def test_start_mounts_source_dir_as_challenge_dir_when_present(monkeypatch) -> None:
    provider, _stopped = _provider(monkeypatch)
    monkeypatch.setattr(htb_challenge, "_start_and_wait_for_ready", lambda *_a, **_k: ("1.2.3.4", 1337))
    ctx = RunContext.create(Path.cwd())
    manifest = Manifest(raw={
        "id": "htb/challenges/baby-time-capsule", "provider": "htb_challenge",
        "source_dir": "data/htb/baby-time-capsule",
        "target": {"challenge_name": "Baby Time Capsule"},
    })

    handle = provider.start(manifest, ctx, _Recorder())

    assert handle.metadata["challenge_dir"] == str(manifest.source_dir)


def test_start_omits_challenge_dir_when_no_source_dir(monkeypatch) -> None:
    provider, _stopped = _provider(monkeypatch)
    monkeypatch.setattr(htb_challenge, "_start_and_wait_for_ready", lambda *_a, **_k: ("1.2.3.4", 1337))
    ctx = RunContext.create(Path.cwd())

    handle = provider.start(_manifest(), ctx, _Recorder())

    assert "challenge_dir" not in handle.metadata


def test_stop_leaves_running_when_not_spawned_by_us(monkeypatch) -> None:
    provider, stopped = _provider(monkeypatch)
    # start() never ran, so _spawned_by_us is still False (default).
    provider.stop(handle=None, manifest=_manifest(), recorder=_Recorder())

    assert stopped == []


def _jwt(sub: str) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"sub": sub}).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.sig"


def test_decode_jwt_user_id_reads_sub_claim() -> None:
    assert htb_challenge._decode_jwt_user_id(_jwt("696862")) == "696862"


def test_decode_jwt_user_id_rejects_non_jwt() -> None:
    with pytest.raises(RuntimeError, match="could not read a user id"):
        htb_challenge._decode_jwt_user_id("not-a-jwt")
