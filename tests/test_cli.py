from pathlib import Path

from bench_orchestrator.cli import main


def test_cli_generates_vulhub_manifest(tmp_path: Path) -> None:
    scenario = tmp_path / "vulhub" / "app" / "case"
    scenario.mkdir(parents=True)
    (scenario / "docker-compose.yml").write_text(
        """
services:
  app:
    image: example/app
    ports:
      - "8080:80"
""",
        encoding="utf-8",
    )
    output = tmp_path / "manifests"

    assert main(["generate-vulhub-manifests", "--vulhub-root", str(tmp_path / "vulhub"), "--output", str(output)]) == 0
    assert (output / "app" / "case.generated.yaml").exists()

