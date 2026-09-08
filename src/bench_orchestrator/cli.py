from __future__ import annotations

import argparse
from pathlib import Path

import dotenv
import yaml

from bench_orchestrator.agents.factory import build_agent_adapter
from bench_orchestrator.infra import InfraManager
from bench_orchestrator.models import Manifest, load_manifest
from bench_orchestrator.runner import BenchmarkRunner
from bench_orchestrator.scoring.factory import build_scorers
from bench_orchestrator.targets.factory import build_target_provider
from bench_orchestrator.targets.vulhub import VulhubManifestGenerator

NYUCTF_PREFIX = "nyuctf:"


def _add_common_args(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument("--agent-config", type=Path, required=True,
                           help="YAML file with agent run configuration (adapter, model, kali image, etc.)")
    subparser.add_argument("--root-dir", type=Path, default=Path.cwd())
    subparser.add_argument("--dry-run", action="store_true")
    subparser.add_argument("--pentest-agent-dir", type=Path, default=None,
                           help="Path to the pentest-agent repo (required when adapter is pentest-agent)")
    subparser.add_argument("--agent-image", default=None,
                           help="Docker image for the selected adapter (default: the adapter's own image, "
                                "or the agent config's 'image' key)")
    subparser.add_argument("--nyuctf-repo", type=Path, default=None,
                           help="Path to the NYU CTF Bench repo (required when manifest is a nyuctf: reference)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bench-orchestrator")
    subcommands = parser.add_subparsers(dest="command", required=True)

    # ------------------------------------------------------------------ #
    # run-task: smoke test or run a single manifest                        #
    # ------------------------------------------------------------------ #
    run_task = subcommands.add_parser("run-task", help="Run a single manifest (infra is provisioned and torn down automatically)")
    run_task.add_argument("manifest", help="YAML manifest path or nyuctf:<challenge_id>")
    _add_common_args(run_task)

    # ------------------------------------------------------------------ #
    # run-benchmark: run every manifest in a directory                     #
    # ------------------------------------------------------------------ #
    run_bench = subcommands.add_parser("run-benchmark", help="Run all manifests in a directory (infra is provisioned and torn down automatically)")
    run_bench.add_argument("manifest_dir",
                           help="Directory of manifest YAMLs (recursive), or 'nyuctf:' for all dataset challenges")
    _add_common_args(run_bench)

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

        manifests = _collect_manifests(args, parser)
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
            for manifest in manifests:
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


def _collect_manifests(args: argparse.Namespace, parser: argparse.ArgumentParser) -> list[Manifest]:
    """Resolve manifest references to Manifest objects.

    Supports YAML file paths and ``nyuctf:<challenge_id>`` dataset references.
    """
    if args.command == "run-task":
        ref = args.manifest
        if ref.startswith(NYUCTF_PREFIX):
            return [_resolve_nyuctf(ref.removeprefix(NYUCTF_PREFIX), args, parser)]
        return [load_manifest(Path(ref))]

    # run-benchmark
    ref = args.manifest_dir
    if ref.startswith(NYUCTF_PREFIX):
        challenge_id = ref.removeprefix(NYUCTF_PREFIX)
        ds = _require_nyuctf_dataset(args, parser)
        if challenge_id:
            return [ds.get_manifest(challenge_id)]
        return [ds.get_manifest(cid) for cid in ds.list_challenges()]

    path = Path(ref)
    if path.is_dir():
        return [load_manifest(p) for p in sorted(path.rglob("*.yaml"))]
    with path.open(encoding="utf-8") as fh:
        contents = yaml.safe_load(fh)
    if isinstance(contents, list):
        return [load_manifest(Path(entry)) for entry in sorted(contents)]
    return [load_manifest(path)]


def _resolve_nyuctf(challenge_id: str, args: argparse.Namespace, parser: argparse.ArgumentParser) -> Manifest:
    ds = _require_nyuctf_dataset(args, parser)
    return ds.get_manifest(challenge_id)


def _require_nyuctf_dataset(args: argparse.Namespace, parser: argparse.ArgumentParser):
    from bench_orchestrator.datasets.nyuctf import NyuCtfDataset
    repo = getattr(args, "nyuctf_repo", None)
    if not repo:
        parser.error("--nyuctf-repo is required when using nyuctf: references")
    return NyuCtfDataset(repo, include_removed=True)


if __name__ == "__main__":
    raise SystemExit(main())
