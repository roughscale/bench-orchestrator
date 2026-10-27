"""VerifiedFlagsScorer - trusts the agent's own already-verified result
(cai's submit_flag tool decides correctness live, during the run) rather
than re-deriving or re-checking anything itself. Replaces the earlier
HtbChallengeFlagScorer/HtbMachineFlagScorer, which resubmitted to HTB's
real API a second time after the run - redundant once verification already
happened live."""
from bench_orchestrator.models import AgentResult, Manifest, TargetHandle
from bench_orchestrator.scoring.verified_flags import VerifiedFlagsScorer


def _manifest() -> Manifest:
    return Manifest(raw={"id": "htb/challenges/x", "provider": "static_host"})


def _target() -> TargetHandle:
    return TargetHandle(provider="static_host", target_id="x")


def test_fails_when_no_flags_reported() -> None:
    scorer = VerifiedFlagsScorer()
    result = scorer.evaluate(_manifest(), _target(), AgentResult(status="failed", summary="", metadata={"flags": [], "flags_required": 1}))

    assert result.passed is False
    assert result.evidence["flags"] == []


def test_passes_when_enough_flags_reported() -> None:
    scorer = VerifiedFlagsScorer()
    result = scorer.evaluate(
        _manifest(), _target(),
        AgentResult(status="completed", summary="", metadata={"flags": ["HTB{real}"], "flags_required": 1}),
    )

    assert result.passed is True
    assert result.evidence["flags"] == ["HTB{real}"]


def test_requires_all_flags_for_a_two_flag_machine() -> None:
    scorer = VerifiedFlagsScorer()
    only_user = scorer.evaluate(
        _manifest(), _target(),
        AgentResult(status="failed", summary="", metadata={"flags": ["a" * 32], "flags_required": 2}),
    )
    both = scorer.evaluate(
        _manifest(), _target(),
        AgentResult(status="completed", summary="", metadata={"flags": ["a" * 32, "b" * 32], "flags_required": 2}),
    )

    assert only_user.passed is False
    assert both.passed is True


def test_defaults_flags_required_to_one_when_missing() -> None:
    scorer = VerifiedFlagsScorer()
    result = scorer.evaluate(_manifest(), _target(), AgentResult(status="completed", summary="", metadata={"flags": ["x"]}))

    assert result.passed is True
    assert result.evidence["flags_required"] == 1
