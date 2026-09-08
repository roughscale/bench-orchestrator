from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bench_orchestrator.models import Manifest


_CATEGORY_ABBREV = {
    "crypto": "cry",
    "forensics": "for",
    "misc": "msc",
    "pwn": "pwn",
    "rev": "rev",
    "web": "web",
}

_EVENT_ABBREV = {
    "CSAW-Quals": "q",
    "CSAW-Finals": "f",
}


def _make_challenge_id(year: str, event: str, category: str, challenge_name: str) -> str:
    """Build a challenge ID matching the NYU CTF Bench key convention.

    Example: ``2023q-cry-blocky_noncense``
    """
    event_suffix = _EVENT_ABBREV.get(event, event[0].lower() if event else "x")
    cat_abbrev = _CATEGORY_ABBREV.get(category, category[:3])
    safe_name = challenge_name.replace("'", "_").replace(" ", "_").replace("-", "_")
    return f"{year}{event_suffix}-{cat_abbrev}-{safe_name}"


class NyuCtfDataset:
    """Load NYU CTF Bench challenges and produce Manifest objects at runtime.

    The NYU CTF Bench repo is the single source of truth — no YAML manifests
    are generated.  Each challenge's ``challenge.json`` provides the flag,
    port, category, and Docker configuration needed to construct a Manifest.

    When ``include_removed=True``, the ``removed/`` directory is scanned
    and its challenges are added to the index.  This covers challenges that
    NYU excluded from their active benchmark but whose files remain in the
    repo (e.g. ``blocky noncense``).
    """

    def __init__(self, repo_root: Path, dataset: str = "test", include_removed: bool = False):
        self.repo_root = repo_root.resolve()
        dataset_file = self.repo_root / f"{dataset}_dataset.json"
        if not dataset_file.exists():
            raise FileNotFoundError(f"dataset file not found: {dataset_file}")
        with dataset_file.open(encoding="utf-8") as fh:
            self._index: dict[str, dict[str, Any]] = json.load(fh)
        if include_removed:
            self._scan_removed()

    def list_challenges(self) -> list[str]:
        return sorted(self._index.keys())

    def filter(
        self,
        *,
        category: str | None = None,
        year: str | None = None,
        event: str | None = None,
    ) -> list[str]:
        results: list[str] = []
        for cid, entry in self._index.items():
            if category and entry.get("category") != category:
                continue
            if year and entry.get("year") != year:
                continue
            if event and entry.get("event") != event:
                continue
            results.append(cid)
        return sorted(results)

    def _scan_removed(self) -> None:
        """Walk the removed/ directory and add entries to the index."""
        removed_root = self.repo_root / "removed"
        if not removed_root.is_dir():
            return
        for challenge_json in removed_root.rglob("challenge.json"):
            challenge_dir = challenge_json.parent
            rel = challenge_dir.relative_to(removed_root)
            # Expected structure: year/event/category/challenge_name
            parts = rel.parts
            if len(parts) < 4:
                continue
            year, event, category = parts[0], parts[1], parts[2]
            challenge_name = str(Path(*parts[3:]))
            cid = _make_challenge_id(year, event, category, challenge_name)
            if cid not in self._index:
                self._index[cid] = {
                    "year": year,
                    "event": event,
                    "category": category,
                    "challenge": challenge_name,
                    "path": str(Path("removed") / rel),
                    "removed": True,
                }

    def get_manifest(self, challenge_id: str) -> Manifest:
        entry = self._index.get(challenge_id)
        if entry is None:
            raise KeyError(f"challenge not found in dataset: {challenge_id}")

        challenge_dir = self.repo_root / entry["path"]
        challenge_json_path = challenge_dir / "challenge.json"
        if not challenge_json_path.exists():
            raise FileNotFoundError(f"challenge.json not found: {challenge_json_path}")

        with challenge_json_path.open(encoding="utf-8") as fh:
            challenge: dict[str, Any] = json.load(fh)

        has_compose = bool(challenge.get("compose"))
        compose_file = challenge_dir / "docker-compose.yml"
        if has_compose and not compose_file.exists():
            compose_file = challenge_dir / "docker-compose.yaml"
            if not compose_file.exists():
                has_compose = False

        internal_port = challenge.get("internal_port")
        box = challenge.get("box", "target")

        raw: dict[str, Any] = {
            "id": f"nyuctf/{challenge_id}",
            "provider": "nyuctf",
            "source_dir": str(challenge_dir),
            "benchmark": {
                "dataset": "nyuctf",
                "year": entry.get("year"),
                "event": entry.get("event"),
                "category": entry.get("category"),
                "challenge": entry.get("challenge"),
                "reference": challenge.get("reference"),
                "author": challenge.get("author"),
                "description": challenge.get("description"),
                "files": challenge.get("files", []),
            },
            "target": {
                "requires_compose": has_compose,
                "startup_timeout_seconds": 120,
            },
            "goal": {
                "kind": "ctf_flag",
                "success": [{"type": "flag", "value": challenge["flag"]}],
            },
            "evidence": {
                "save_container_logs": has_compose,
            },
        }

        if has_compose and internal_port:
            raw["network"] = {
                "target_alias": box,
                "exposed_ports": [f"{internal_port}/tcp"],
            }
            raw["target"]["health"] = [
                {"type": "tcp", "host": box, "port": int(internal_port)},
            ]

        return Manifest(raw=raw)
