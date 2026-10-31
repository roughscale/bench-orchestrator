"""htb_flag_verify_server.py - the local HTTP server that lets a cai
container's submit_flag tool get real HTB verification (via
CHALLENGE_FLAG_VERIFY_URL) instead of a local shape/exact match."""
import requests

from bench_orchestrator.agents import htb_flag_verify_server as module
from bench_orchestrator.agents.htb_flag_verify_server import (
    FlagVerifyServer,
    build_verify_server,
)
from bench_orchestrator.models import Manifest, TargetHandle


class _FakeResponse:
    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.text = message
        self._message = message

    def json(self):
        return {"message": self._message}


def test_verify_challenge_flag_accepts_on_200(monkeypatch) -> None:
    monkeypatch.setattr(module.requests, "post", lambda *a, **k: _FakeResponse(200, "Congratulations!"))

    correct, message = module._verify_challenge_flag("key", 360, "HTB{real}")

    assert correct is True
    assert message == "Congratulations!"


def test_verify_challenge_flag_rejects_known_wrong_statuses(monkeypatch) -> None:
    for status in (400, 403, 422):
        monkeypatch.setattr(module.requests, "post", lambda *a, **k: _FakeResponse(status, "Incorrect flag."))
        correct, _ = module._verify_challenge_flag("key", 360, "HTB{wrong}")
        assert correct is False


def test_verify_challenge_flag_accepts_already_owned_on_400(monkeypatch) -> None:
    # A correct flag for a pre-owned challenge comes back as 400 "Challenge
    # already solved" (status + body confirmed live). HTB validates the flag
    # before returning that, so it counts as correct.
    for message in ("Challenge already solved", "You have already owned this challenge"):
        monkeypatch.setattr(module.requests, "post", lambda *a, **k: _FakeResponse(400, message))
        correct, returned = module._verify_challenge_flag("key", 360, "HTB{real}")
        assert correct is True
        assert returned == message


def test_verify_challenge_flag_already_owned_message_only_counts_on_400(monkeypatch) -> None:
    # The already-owned verdict is a 400-only signal; 403/422 stay rejections
    # even if some message happened to contain "already".
    for status in (403, 422):
        monkeypatch.setattr(module.requests, "post", lambda *a, **k: _FakeResponse(status, "already solved"))
        correct, _ = module._verify_challenge_flag("key", 360, "HTB{real}")
        assert correct is False


def test_verify_challenge_flag_raises_on_unexpected_status(monkeypatch) -> None:
    monkeypatch.setattr(module.requests, "post", lambda *a, **k: _FakeResponse(500, "server error"))

    try:
        module._verify_challenge_flag("key", 360, "HTB{x}")
        raised = False
    except RuntimeError:
        raised = True
    assert raised


def test_verify_machine_flag_accepts_on_200(monkeypatch) -> None:
    monkeypatch.setattr(module.requests, "post", lambda *a, **k: _FakeResponse(200, "Congratulations!"))

    correct, message = module._verify_machine_flag("key", 351, "deadbeef" * 4)

    assert correct is True


def test_verify_machine_flag_rejects_400(monkeypatch) -> None:
    monkeypatch.setattr(module.requests, "post", lambda *a, **k: _FakeResponse(400, "Incorrect Flag."))

    correct, _ = module._verify_machine_flag("key", 351, "wrong")

    assert correct is False


def test_verify_machine_flag_records_raw_response(monkeypatch) -> None:
    # The verify server runs host-side with no agent-visible output, so the
    # raw HTB response (status + body + submitted flag) is recorded as an
    # event - the only place a re-run can see why a correct-looking flag was
    # rejected, since the status is otherwise discarded.
    monkeypatch.setattr(module.requests, "post", lambda *a, **k: _FakeResponse(400, "Incorrect Flag."))
    events = []

    class _Rec:
        def event(self, phase, payload):
            events.append((phase, payload))

    module._verify_machine_flag("key", 351, "deadbeef" * 4, _Rec())

    assert len(events) == 1
    phase, payload = events[0]
    assert phase == "flag_verify_response"
    assert payload["status_code"] == 400
    assert payload["body"] == "Incorrect Flag."
    assert payload["flag"] == "deadbeef" * 4
    assert payload["machine_id"] == 351


def test_build_verify_server_uses_target_metadata_challenge_id(monkeypatch) -> None:
    resolved = []
    monkeypatch.setattr(module, "_resolve_challenge_id", lambda *a, **k: resolved.append(1))
    calls = []
    monkeypatch.setattr(module, "_verify_challenge_flag", lambda api_key, cid, flag: calls.append(cid) or (True, "ok"))

    manifest = Manifest(raw={"id": "x", "provider": "htb_challenge"})
    target = TargetHandle(provider="htb_challenge", target_id="x", metadata={"challenge_id": 360})

    server = build_verify_server(manifest, target, "key")
    server.start()  # stop() deadlocks (shutdown() waits on serve_forever's loop) if never started
    try:
        assert resolved == []  # never needed to look it up
        server._httpd.verify_fn("HTB{x}")  # type: ignore[attr-defined]
        assert calls == [360]
    finally:
        server.stop()


def test_build_verify_server_resolves_challenge_id_by_name_for_static_host(monkeypatch) -> None:
    monkeypatch.setattr(module, "_resolve_challenge_id", lambda api_key, name: 469)
    calls = []
    monkeypatch.setattr(module, "_verify_challenge_flag", lambda api_key, cid, flag: calls.append(cid) or (True, "ok"))

    manifest = Manifest(raw={"id": "x", "provider": "static_host", "benchmark": {"platform": "htb", "challenge_name": "Alien Cradle"}})
    target = TargetHandle(provider="static_host", target_id="x")  # no challenge_id in metadata

    server = build_verify_server(manifest, target, "key")
    server.start()
    try:
        server._httpd.verify_fn("HTB{x}")  # type: ignore[attr-defined]
        assert calls == [469]
    finally:
        server.stop()


def test_build_verify_server_falls_back_to_machine_id(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(module, "_verify_machine_flag", lambda api_key, mid, flag, recorder=None: calls.append(mid) or (True, "ok"))

    manifest = Manifest(raw={"id": "x", "provider": "htb"})
    target = TargetHandle(provider="htb", target_id="x", metadata={"machine_id": 351})

    server = build_verify_server(manifest, target, "key")
    server.start()
    try:
        server._httpd.verify_fn("deadbeef")  # type: ignore[attr-defined]
        assert calls == [351]
    finally:
        server.stop()


def test_build_verify_server_returns_none_when_nothing_resolvable() -> None:
    manifest = Manifest(raw={"id": "x", "provider": "static_host"})
    target = TargetHandle(provider="static_host", target_id="x")

    assert build_verify_server(manifest, target, "key") is None


def test_end_to_end_http_round_trip() -> None:
    """No mocking - a real local server, a real HTTP POST, confirming the
    actual wire protocol submit_flag_tool.py expects to talk to."""
    server = FlagVerifyServer(lambda flag: (flag == "HTB{real}", f"checked {flag}"))
    server.start()
    try:
        resp = requests.post(f"http://127.0.0.1:{server.port}/verify", json={"flag": "HTB{real}"}, timeout=5)
        assert resp.json() == {"correct": True, "message": "checked HTB{real}"}

        resp = requests.post(f"http://127.0.0.1:{server.port}/verify", json={"flag": "HTB{wrong}"}, timeout=5)
        assert resp.json() == {"correct": False, "message": "checked HTB{wrong}"}
    finally:
        server.stop()


def test_end_to_end_http_survives_verify_fn_raising() -> None:
    def boom(flag: str):
        raise ConnectionError("HTB unreachable")

    server = FlagVerifyServer(boom)
    server.start()
    try:
        resp = requests.post(f"http://127.0.0.1:{server.port}/verify", json={"flag": "x"}, timeout=5)
        body = resp.json()
        assert body["correct"] is False
        assert "HTB unreachable" in body["message"]
    finally:
        server.stop()
