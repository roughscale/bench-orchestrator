#!/usr/bin/env python3
"""Download the file-based HTB Challenge/Sherlock artifacts referenced by
manifests/htb/challenges/*.yaml into their source_dir, so the cai agent
actually has files to analyse (StaticHostTargetProvider mounts source_dir
into the container - it never downloads anything itself).

HTB Labs' consumer API is undocumented (see HtbTargetProvider for the same
caveat on the Machines side). This reuses the same reverse-engineered
conventions: v4 keyword search for name -> id, and a User-Agent that isn't
the default python-requests string (Cloudflare bot-mitigates on that - see
htb.py's own note).

Endpoints used (challenges only - no Sherlock download endpoint has been
found or tested; Sherlocks resolve to a numeric id if found, but are
reported as "download not implemented" rather than guessed at):
  GET /api/v4/challenges?keyword=<name>   -> resolve name to numeric id
  GET /api/v4/challenge/download/{id}     -> 302 to a presigned S3 zip URL
Zips are password-protected with HTB's standard challenge zip password
("hackthebox").

Usage:
    python tools/fetch_htb_challenge_files.py [--force] [--manifests-dir DIR]

Requires HTB_API_KEY in the environment or a .env file (same as
bench-orchestrator's own HtbTargetProvider).
"""
from __future__ import annotations

import argparse
import io
import os
import re
import sys
import time
import zipfile
from pathlib import Path
from typing import Any

import requests
import yaml
from dotenv import load_dotenv

_API_BASE = "https://labs.hackthebox.com/api/v4"
_ZIP_PASSWORD = b"hackthebox"
_DOWNLOAD_ENDPOINT = {"challenge": "challenge", "sherlock": None}
_SEARCH_ENDPOINT = {"challenge": "challenges", "sherlock": "sherlocks"}


def _headers(api_key: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
        # Cloudflare bot-mitigates the default python-requests/x.y UA - see
        # bench_orchestrator/targets/htb.py::_api_headers for the live-tested
        # root cause. Reuse the same fix here.
        "User-Agent": "curl/8.5.0",
    }


def _resolve_id(api_key: str, name: str, kind: str) -> tuple[int | None, list[str]]:
    endpoint = _SEARCH_ENDPOINT[kind]
    resp = requests.get(
        f"{_API_BASE}/{endpoint}", params={"keyword": name, "per_page": 15},
        headers=_headers(api_key), timeout=15,
    )
    resp.raise_for_status()
    candidates = resp.json().get("data", [])
    matches = [c for c in candidates if str(c.get("name", "")).lower() == name.lower()]
    if not matches:
        return None, [str(c.get("name")) for c in candidates]
    if len(matches) > 1:
        raise RuntimeError(f"'{name}' matched multiple {kind}s: {[m.get('id') for m in matches]}")
    return int(matches[0]["id"]), []


def _download_zip(api_key: str, item_id: int, kind: str) -> bytes:
    endpoint = _DOWNLOAD_ENDPOINT[kind]
    if endpoint is None:
        raise RuntimeError(f"no known download endpoint for kind={kind!r}")
    resp = requests.get(
        f"{_API_BASE}/{endpoint}/download/{item_id}",
        headers=_headers(api_key), timeout=60, allow_redirects=True,
    )
    resp.raise_for_status()
    return resp.content


_REDACTION_MARKER = "[REDACTED_PLACEHOLDER_FLAG]"


def _flag_pattern(manifest: dict[str, Any]) -> re.Pattern[str] | None:
    for entry in manifest.get("goal", {}).get("success", []):
        if entry.get("type") == "flag_pattern" and entry.get("pattern"):
            return re.compile(str(entry["pattern"]))
    return None


def _redact_planted_flags(dest: Path, flag_pattern: re.Pattern[str]) -> int:
    """Some HTB challenge zips ship a flag-shaped literal in their own
    source - not the real per-instance answer, just something that happens
    to satisfy the scoring regex. Two confirmed live: a networked
    challenge's server source containing the placeholder
    `FLAG = b'HTB{--REDACTED--}'` (the real flag is only ever injected into
    a live instance, never the download), and a leftover local-testing
    flag.txt (`HTB{f4k3_fl4g_f0r_t3st1ng}`). Left in place, an agent can
    "solve" the challenge just by reading a file we handed it. Scrub any
    such literal out before these files are ever mounted into a container.

    Returns the number of files redacted.
    """
    redacted = 0
    for path in dest.rglob("*"):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary file - not a plausible place for a planted literal
        new_text, n = flag_pattern.subn(_REDACTION_MARKER, text)
        if n:
            path.write_text(new_text, encoding="utf-8")
            redacted += 1
    return redacted


def _extract(blob: bytes, dest: Path, flag_pattern: re.Pattern[str] | None) -> tuple[int, int]:
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        try:
            zf.extractall(dest, pwd=_ZIP_PASSWORD)
        except RuntimeError:
            # Not every challenge zip is password-protected.
            zf.extractall(dest)
        n_files = len(zf.namelist())
    n_redacted = _redact_planted_flags(dest, flag_pattern) if flag_pattern else 0
    return n_files, n_redacted


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifests-dir", type=Path, default=Path("manifests/htb/challenges"))
    parser.add_argument("--force", action="store_true", help="re-download even if source_dir already has files")
    args = parser.parse_args()

    load_dotenv()
    api_key = os.environ.get("HTB_API_KEY")
    if not api_key:
        print("HTB_API_KEY not set (checked environment and .env)", file=sys.stderr)
        return 1

    manifest_paths = sorted(args.manifests_dir.glob("*.yaml"))
    if not manifest_paths:
        print(f"no manifests found under {args.manifests_dir}", file=sys.stderr)
        return 1

    ok: list[str] = []
    skipped: list[str] = []
    missing: list[str] = []
    errors: list[str] = []

    for path in manifest_paths:
        data: dict[str, Any] = yaml.safe_load(path.read_text())
        benchmark = data.get("benchmark", {})
        name = benchmark.get("challenge_name")
        kind = benchmark.get("challenge_type", "challenge")

        if not name:
            print(f"SKIP  {path.name}: no benchmark.challenge_name")
            continue

        # Live-target challenges (provider: htb_challenge, e.g. Diagnostic)
        # have nothing to download - HtbChallengeTargetProvider provisions
        # them directly against the API instead.
        if "source_dir" not in data:
            print(f"skip  {name} - not a file-based challenge (no source_dir)")
            continue
        source_dir = Path(data["source_dir"])

        if source_dir.exists() and any(source_dir.iterdir()) and not args.force:
            print(f"skip  {name} - already present at {source_dir}")
            skipped.append(name)
            continue

        try:
            item_id, near_misses = _resolve_id(api_key, name, kind)
        except Exception as exc:
            print(f"ERROR {name}: resolving id failed: {exc}")
            errors.append(name)
            continue

        if item_id is None:
            hint = f" (closest keyword matches: {near_misses[:5]})" if near_misses else ""
            print(f"MISS  {name} ({kind}) - not found in the live HTB catalog{hint}")
            missing.append(name)
            continue

        try:
            blob = _download_zip(api_key, item_id, kind)
            n_files, n_redacted = _extract(blob, source_dir, _flag_pattern(data))
            redacted_note = f", {n_redacted} file(s) had a planted flag redacted" if n_redacted else ""
            print(f"OK    {name} (id={item_id}) -> {source_dir} ({n_files} files{redacted_note})")
            ok.append(name)
        except Exception as exc:
            print(f"ERROR {name} (id={item_id}): {exc}")
            errors.append(name)

        # The download endpoint is rate-limited (observed x-ratelimit-limit: 15
        # per window) - stay well under that between calls.
        time.sleep(2)

    print()
    print(f"=== done: {len(ok)} downloaded, {len(skipped)} already present, "
          f"{len(missing)} not found, {len(errors)} errored ===")
    if missing:
        print("not found:", ", ".join(missing))
    if errors:
        print("errored:", ", ".join(errors))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
