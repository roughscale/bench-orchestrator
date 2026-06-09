from pathlib import Path

import yaml

from bench_orchestrator.targets.vulhub import VulhubManifestGenerator, extract_ports


def test_extract_ports_from_compose(tmp_path: Path) -> None:
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        """
services:
  app:
    image: example/app
    ports:
      - "8080:80"
      - target: 8443
        published: 9443
        protocol: tcp
""",
        encoding="utf-8",
    )

    assert extract_ports(compose) == ["80/tcp", "8443/tcp"]


def test_generate_draft_manifest(tmp_path: Path) -> None:
    scenario = tmp_path / "shiro" / "CVE-2016-4437"
    scenario.mkdir(parents=True)
    (scenario / "docker-compose.yml").write_text(
        """
services:
  app:
    image: example/app
    ports:
      - "8080:8080"
""",
        encoding="utf-8",
    )

    manifests = VulhubManifestGenerator(tmp_path).generate()

    assert len(manifests) == 1
    manifest = manifests[0]
    assert manifest["id"] == "vulhub/shiro/cve-2016-4437"
    assert manifest["provider"] == "vulhub"
    assert manifest["network"]["exposed_ports"] == ["8080/tcp"]
    assert manifest["goal"]["success"] == [{"type": "needs_curation"}]


def test_write_manifest(tmp_path: Path) -> None:
    scenario = tmp_path / "app" / "case"
    scenario.mkdir(parents=True)
    (scenario / "compose.yaml").write_text("services: {app: {image: example/app}}\n", encoding="utf-8")

    output = tmp_path / "out"
    paths = VulhubManifestGenerator(tmp_path).write(output)

    assert len(paths) == 1
    raw = yaml.safe_load(paths[0].read_text(encoding="utf-8"))
    assert raw["curation"]["status"] == "needs_success_criteria"

