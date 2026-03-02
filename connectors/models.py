from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class PreparedCommand:
    tool: str
    target: str
    command: list[str]
    timeout_seconds: int
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CommandExecution:
    command: list[str]
    return_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    error: str | None = None


@dataclass
class ConnectorResult:
    tool: str
    target: str
    status: str
    command: list[str]
    return_code: int
    duration_ms: int
    timed_out: bool
    parsed: dict[str, Any]
    findings: list[dict[str, Any]]
    validation: dict[str, Any]
    error: str | None = None
    stdout: str = ""
    stderr: str = ""
    gate: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

