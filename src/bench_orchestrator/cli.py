from __future__ import annotations

import argparse
from pathlib import Path

import dotenv

from bench_orchestrator.agents.factory import build_agent_adapter
from bench_orchestrator.models import load_manifest
from bench_orchestrator.runner import BenchmarkRunner
from bench_orchestrator.scoring.factory import build_scorers
from bench_orchestrator.targets.factory import build_target_provider
from bench_orchestrator.targets.vulhub import VulhubManifestGenerator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bench-orchestrator")
    subcommands = parser.add_subparsers(dest="command", required=True)

    generate = subcommands.add_parser("generate-vulhub-manifests", help="Generate draft manifests from a Vulhub checkout")
    generate.add_argument("--vulhub-root", required=True, type=Path)
    generate.add_argument("--output", required=True, type=Path)

    run_task = subcommands.add_parser("run-task", help="Run one manifest")
    run_task.add_argument("manifest", type=Path)
    run_task.add_argument("--root-dir", type=Path, default=Path.cwd())
    run_task.add_argument("--dry-run", action="store_true")
    run_task.add_argument(
        "--pentest-agent-dir",
        type=Path,
        default=None,
        help="Path to the pentest-agent repo (required when adapter is pentest-agent)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    dotenv.load_dotenv()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "generate-vulhub-manifests":
        paths = VulhubManifestGenerator(args.vulhub_root).write(args.output)
        for path in paths:
            print(path)
        return 0

    if args.command == "run-task":
        manifest = load_manifest(args.manifest)
        provider = build_target_provider(manifest.provider)
        adapter = build_agent_adapter(manifest.agent_adapter, pentest_agent_dir=args.pentest_agent_dir)
        scorer_configs = manifest.raw.get("goal", {}).get("success", [])
        scorers = build_scorers(scorer_configs)
        runner = BenchmarkRunner(provider, adapter, scorers, root_dir=args.root_dir, dry_run=args.dry_run)
        scores = runner.run_task(manifest)
        for score in scores:
            print(f"{score.scorer}: {'pass' if score.passed else 'fail'}")
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
