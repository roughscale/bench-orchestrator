from __future__ import annotations

import argparse
from pathlib import Path

import dotenv
import yaml

from bench_orchestrator.agents.factory import build_agent_adapter
from bench_orchestrator.infra import InfraManager
from bench_orchestrator.models import load_manifest
from bench_orchestrator.runner import BenchmarkRunner
from bench_orchestrator.scoring.factory import build_scorers
from bench_orchestrator.targets.factory import build_target_provider
from bench_orchestrator.targets.vulhub import VulhubManifestGenerator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bench-orchestrator")
    subcommands = parser.add_subparsers(dest="command", required=True)

    # ------------------------------------------------------------------ #
    # run-task: smoke test or run a single manifest                        #
    # ------------------------------------------------------------------ #
    run_task = subcommands.add_parser("run-task", help="Run a single manifest (infra is provisioned and torn down automatically)")
    run_task.add_argument("manifest", type=Path)
    run_task.add_argument("--agent-config", type=Path, required=True,
                          help="YAML file with agent run configuration (adapter, model, kali image, etc.)")
    run_task.add_argument("--root-dir", type=Path, default=Path.cwd())
    run_task.add_argument("--dry-run", action="store_true")
    run_task.add_argument("--pentest-agent-dir", type=Path, default=None,
                          help="Path to the pentest-agent repo (required when adapter is pentest-agent)")
    run_task.add_argument("--agent-image", default=None,
                          help="Docker image for the selected adapter (default: the adapter's own image, "
                               "or the agent config's 'image' key)")

    # ------------------------------------------------------------------ #
    # run-benchmark: run every manifest in a directory                     #
    # ------------------------------------------------------------------ #
    run_bench = subcommands.add_parser("run-benchmark", help="Run all manifests in a directory (infra is provisioned and torn down automatically)")
    run_bench.add_argument("manifest_dir", type=Path,
                           help="Directory containing manifest YAML files (searched recursively)")
    run_bench.add_argument("--agent-config", type=Path, required=True)
    run_bench.add_argument("--root-dir", type=Path, default=Path.cwd())
    run_bench.add_argument("--dry-run", action="store_true")
    run_bench.add_argument("--pentest-agent-dir", type=Path, default=None)
    run_bench.add_argument("--agent-image", default=None,
                           help="Docker image for the selected adapter (default: the adapter's own image, "
                                "or the agent config's 'image' key)")

    # ------------------------------------------------------------------ #
    # generate-vulhub-manifests                                            #
    # ------------------------------------------------------------------ #
    generate = subcommands.add_parser("generate-vulhub-manifests", help="Generate draft manifests from a Vulhub checkout")
    generate.add_argument("--vulhub-root", required=True, type=Path)
    generate.add_argument("--output", required=True, type=Path)

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

    if args.command in ("run-task", "run-benchmark"):
        with args.agent_config.open(encoding="utf-8") as fh:
            agent_config = yaml.safe_load(fh) or {}
        adapter_name = agent_config.get("adapter")
        if not adapter_name:
            parser.error("--agent-config must specify 'adapter'")

        manifests = _collect_manifests(args)
        if not manifests:
            parser.error("no manifests found")

        adapter = build_agent_adapter(
            adapter_name,
            pentest_agent_dir=args.pentest_agent_dir,
            agent_config=agent_config,
            image=args.agent_image,
        )

        overall_rc = 0
        with InfraManager(adapter.compose_file, agent_config):
            for manifest_path in manifests:
                manifest = load_manifest(manifest_path)
                provider = build_target_provider(manifest.provider)
                scorer_configs = manifest.raw.get("goal", {}).get("success", [])
                scorers = build_scorers(scorer_configs)
                runner = BenchmarkRunner(
                    provider, adapter, scorers,
                    root_dir=args.root_dir,
                    dry_run=args.dry_run,
                )
                print(f"\n=== {manifest.id} ===")
                try:
                    scores = runner.run_task(manifest)
                    for score in scores:
                        status = "pass" if score.passed else "fail"
                        print(f"  {score.scorer}: {status}")
                        if not score.passed:
                            overall_rc = 1
                except Exception as exc:
                    print(f"  error: {exc}")
                    overall_rc = 1

        return overall_rc

    parser.error(f"unknown command: {args.command}")
    return 2


def _collect_manifests(args: argparse.Namespace) -> list[Path]:
    if args.command == "run-task":
        return [args.manifest]
    path = args.manifest_dir
    if path.is_dir():
        return sorted(path.rglob("*.yaml"))
    # It's a file — check if it's a manifest list (YAML list) or a single manifest (YAML dict).
    with path.open(encoding="utf-8") as fh:
        contents = yaml.safe_load(fh)
    if isinstance(contents, list):
        return sorted(Path(entry) for entry in contents)
    return [path]


if __name__ == "__main__":
    raise SystemExit(main())
