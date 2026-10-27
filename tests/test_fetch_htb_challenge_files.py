"""fetch_htb_challenge_files.py's flag-redaction step.

Some HTB challenge zips ship a flag-shaped literal verbatim in their own
source (a networked challenge's placeholder like `HTB{--REDACTED--}`, or a
leftover local-testing flag.txt) - not the real per-instance answer, just
something that happens to satisfy the scoring regex. Confirmed live in
baby-time-capsule and spookifier. Extraction must scrub these out before the
files are ever mounted into an agent's container - see htb_challenge.py's
sibling note and cai_agent.py for where the mounted dir is used.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from fetch_htb_challenge_files import _flag_pattern, _redact_planted_flags  # noqa: E402


def test_flag_pattern_reads_manifest_goal() -> None:
    manifest = {"goal": {"success": [{"type": "flag_pattern", "pattern": r"HTB\{[^}]+\}"}]}}
    pattern = _flag_pattern(manifest)
    assert pattern is not None
    assert pattern.search("here is HTB{abc123}") is not None


def test_flag_pattern_none_when_no_flag_pattern_scorer() -> None:
    assert _flag_pattern({"goal": {"success": [{"type": "http_probe"}]}}) is None
    assert _flag_pattern({}) is None


def test_redact_planted_flags_scrubs_matching_files(tmp_path) -> None:
    import re

    (tmp_path / "server.py").write_text("FLAG = b'HTB{--REDACTED--}'\nprint('hi')\n")
    (tmp_path / "readme.txt").write_text("no flag-shaped text here")
    pattern = re.compile(r"HTB\{[^}]+\}")

    n = _redact_planted_flags(tmp_path, pattern)

    assert n == 1
    server_contents = (tmp_path / "server.py").read_text()
    assert "HTB{--REDACTED--}" not in server_contents
    assert pattern.search(server_contents) is None  # replacement must not itself match
    assert (tmp_path / "readme.txt").read_text() == "no flag-shaped text here"


def test_redact_planted_flags_skips_binary_files(tmp_path) -> None:
    import re

    (tmp_path / "binary.bin").write_bytes(b"\xff\xfe\x00HTB{shouldnt-crash}")
    pattern = re.compile(r"HTB\{[^}]+\}")

    n = _redact_planted_flags(tmp_path, pattern)  # must not raise on undecodable bytes

    assert n == 0
