from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ClientEnvironment:
    """Attacker/tool execution context for one benchmark run."""

    name: str
    network_name: str | None = None
    container_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

