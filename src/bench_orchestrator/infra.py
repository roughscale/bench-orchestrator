from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any


class InfraManager:
    """Manages adapter infrastructure defined by a docker-compose file.

    If compose_file is None the manager is a no-op, allowing adapters that
    require no companion infrastructure to use the same code path.

    The kali image is read from the agent config so it is configured in one place.
    """

    def __init__(self, compose_file: Path | None, agent_config: dict[str, Any]):
        self._compose_file = compose_file
        self._kali_image = agent_config.get("kali", {}).get("image", "kali-headless-base")
        self._env = {**os.environ, "KALI_IMAGE": self._kali_image}

    def start(self) -> None:
        if self._compose_file is None:
            return
        result = subprocess.run(
            ["docker", "compose", "-f", str(self._compose_file), "up", "-d", "--wait"],
            env=self._env,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError("Failed to start benchmark infrastructure")

    def stop(self) -> None:
        if self._compose_file is None:
            return
        subprocess.run(
            ["docker", "compose", "-f", str(self._compose_file), "down"],
            env=self._env,
            check=False,
        )

    def __enter__(self) -> "InfraManager":
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()
