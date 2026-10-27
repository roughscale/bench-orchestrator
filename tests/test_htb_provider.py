"""HtbTargetProvider teardown behaviour - specifically that a machine we
spawn is not leaked when start() fails or is interrupted after the spawn
call but before it returns a handle (the runner only tears down when
start() handed back a handle, so start() has to clean up its own spawn)."""
from pathlib import Path

import pytest

from bench_orchestrator.models import Manifest, RunContext
from bench_orchestrator.targets import htb


class _Recorder:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def event(self, phase: str, payload: dict | None = None) -> None:
        self.events.append((phase, payload or {}))


def _manifest() -> Manifest:
    return Manifest(raw={"id": "htb/example", "provider": "htb", "target": {"machine_name": "Example"}})


def _provider(monkeypatch, *, active_before_spawn=None):
    """An HtbTargetProvider with prepare() already done (machine_id=634) and
    every outbound HTB call stubbed."""
    monkeypatch.setattr(htb, "_vpn_interface_ip", lambda _iface: "10.10.14.9")
    monkeypatch.setattr(htb, "_spawn_machine", lambda *_: None)
    monkeypatch.setattr(htb, "_get_active_machine", lambda *_: active_before_spawn)
    monkeypatch.setattr(htb, "_get_required_flags", lambda *_: 2)

    terminated: list[int] = []
    monkeypatch.setattr(htb, "_terminate_machine", lambda _key, mid: terminated.append(mid))

    provider = htb.HtbTargetProvider()
    provider._api_key = "key"
    provider._machine_id = 634
    return provider, terminated


def test_spawn_then_wait_timeout_terminates_the_spawn(monkeypatch) -> None:
    provider, terminated = _provider(monkeypatch)
    monkeypatch.setattr(
        htb, "_wait_for_ip",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("timed out waiting for IP")),
    )
    ctx = RunContext.create(Path.cwd())

    with pytest.raises(RuntimeError, match="timed out"):
        provider.start(_manifest(), ctx, _Recorder())

    assert terminated == [634]


def test_spawn_then_keyboard_interrupt_terminates_the_spawn(monkeypatch) -> None:
    provider, terminated = _provider(monkeypatch)
    monkeypatch.setattr(
        htb, "_wait_for_ip",
        lambda *_a, **_k: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    ctx = RunContext.create(Path.cwd())

    with pytest.raises(KeyboardInterrupt):
        provider.start(_manifest(), ctx, _Recorder())

    assert terminated == [634]


def test_reused_active_machine_is_not_terminated_on_failure(monkeypatch) -> None:
    # Machine 634 was already up (someone else / a prior run) - we adopt it,
    # so a later failure must NOT tear it down.
    provider, terminated = _provider(
        monkeypatch, active_before_spawn={"id": 634, "name": "Example", "ip": None}
    )
    monkeypatch.setattr(
        htb, "_wait_for_ip",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("timed out waiting for IP")),
    )
    ctx = RunContext.create(Path.cwd())

    with pytest.raises(RuntimeError):
        provider.start(_manifest(), ctx, _Recorder())

    assert terminated == []
    assert provider._spawned_by_us is False


def test_successful_start_returns_handle_and_terminates_nothing(monkeypatch) -> None:
    provider, terminated = _provider(monkeypatch)
    monkeypatch.setattr(htb, "_wait_for_ip", lambda *_a, **_k: "10.129.1.5")
    ctx = RunContext.create(Path.cwd())

    handle = provider.start(_manifest(), ctx, _Recorder())

    assert handle.endpoint == "10.129.1.5"
    assert terminated == []
    assert provider._spawned_by_us is True
