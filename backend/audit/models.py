from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class AuditContext:
    trace_id: str
    task_id: str
    agent_id: str
    operator: str


@dataclass
class AuditEvent:
    event_id: str
    timestamp: str
    trace_id: str
    task_id: str
    agent_id: str
    operator: str
    action: str
    target: str
    tool: str
    decision: str
    reason: str
    input_hash: str
    output_hash: str
    evidence_dir: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def create_audit_context(operator: str, trace_id: str | None, task_id: str | None, agent_id: str | None) -> AuditContext:
    return AuditContext(
        trace_id=(trace_id or str(uuid4())),
        task_id=(task_id or f"task-{uuid4()}"),
        agent_id=(agent_id or "api-gateway"),
        operator=operator,
    )


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")

