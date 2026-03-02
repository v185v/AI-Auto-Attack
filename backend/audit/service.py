from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path
from threading import Lock
from typing import Any
from uuid import uuid4

from backend.audit.models import AuditContext, AuditEvent, utc_now_iso
from backend.core.config import get_settings
from backend.security.redaction import RedactionSettings, get_redaction_settings, redact_payload, redact_text


class AuditService:
    def __init__(
        self,
        evidence_root: str = "evidence",
        write_index: bool = True,
        redaction_settings: RedactionSettings | None = None,
    ) -> None:
        self.evidence_root = Path(evidence_root)
        self.write_index = write_index
        self.redaction_settings = redaction_settings or get_redaction_settings()
        self._lock = Lock()
        self.evidence_root.mkdir(parents=True, exist_ok=True)
        self.index_path = self.evidence_root / "audit-events.jsonl"

    def record_event(
        self,
        *,
        context: AuditContext,
        action: str,
        target: str,
        tool: str,
        decision: str,
        reason: str,
        input_payload: Any,
        output_payload: Any,
        metadata: dict[str, Any] | None = None,
        raw_output: str | None = None,
        attachments: dict[str, bytes | str] | None = None,
    ) -> AuditEvent:
        timestamp = utc_now_iso()
        event_id = uuid4().hex[:16]
        date_dir = timestamp[:10]
        event_dir = self.evidence_root / date_dir / context.trace_id / event_id
        event_dir.mkdir(parents=True, exist_ok=True)

        input_hash = _hash_payload(input_payload)
        output_hash = _hash_payload(output_payload)
        normalized_input = _normalize_payload(input_payload)
        normalized_output = _normalize_payload(output_payload)
        safe_input = redact_payload(normalized_input, self.redaction_settings)
        safe_output = redact_payload(normalized_output, self.redaction_settings)
        safe_metadata = redact_payload(metadata or {}, self.redaction_settings)
        event = AuditEvent(
            event_id=event_id,
            timestamp=timestamp,
            trace_id=context.trace_id,
            task_id=context.task_id,
            agent_id=context.agent_id,
            operator=context.operator,
            action=action,
            target=target,
            tool=tool,
            decision=decision,
            reason=reason,
            input_hash=input_hash,
            output_hash=output_hash,
            evidence_dir=event_dir.as_posix(),
            metadata=safe_metadata if isinstance(safe_metadata, dict) else {},
        )

        self._write_json(event_dir / "event.json", event.to_dict())
        self._write_json(event_dir / "input.json", safe_input)
        self._write_json(event_dir / "output.json", safe_output)

        if raw_output:
            safe_raw = redact_text(raw_output, self.redaction_settings)
            (event_dir / "raw_output.txt").write_text(safe_raw, encoding="utf-8")
        if attachments:
            attachments_dir = event_dir / "attachments"
            attachments_dir.mkdir(parents=True, exist_ok=True)
            for name, content in attachments.items():
                safe_name = _safe_filename(name)
                file_path = attachments_dir / safe_name
                if isinstance(content, bytes):
                    file_path.write_bytes(content)
                else:
                    file_path.write_text(
                        redact_text(str(content), self.redaction_settings),
                        encoding="utf-8",
                    )

        if self.write_index:
            self._append_index(event)

        return event

    def query_events(
        self,
        *,
        trace_id: str | None = None,
        task_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        events = self._read_index_events()
        filtered = []
        for event in events:
            if trace_id and event.get("trace_id") != trace_id:
                continue
            if task_id and event.get("task_id") != task_id:
                continue
            filtered.append(event)

        filtered.sort(key=lambda item: str(item.get("timestamp", "")), reverse=True)
        total = len(filtered)
        start = max(offset, 0)
        end = start + max(limit, 0)
        items = filtered[start:end]

        return {
            "total": total,
            "offset": start,
            "limit": max(limit, 0),
            "items": items,
        }

    def _append_index(self, event: AuditEvent) -> None:
        line = json.dumps(event.to_dict(), ensure_ascii=True)
        with self._lock:
            with self.index_path.open("a", encoding="utf-8") as file_obj:
                file_obj.write(line + "\n")

    def _read_index_events(self) -> list[dict[str, Any]]:
        if not self.index_path.exists():
            return []

        events: list[dict[str, Any]] = []
        with self.index_path.open("r", encoding="utf-8") as file_obj:
            for raw_line in file_obj:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(parsed, dict):
                    events.append(parsed)
        return events

    @staticmethod
    def _write_json(path: Path, payload: Any) -> None:
        text = json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True, default=str)
        path.write_text(text + "\n", encoding="utf-8")


def _normalize_payload(payload: Any) -> Any:
    if payload is None:
        return {}
    return payload


def _hash_payload(payload: Any) -> str:
    normalized = _normalize_payload(payload)
    encoded = json.dumps(normalized, ensure_ascii=True, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _safe_filename(name: str) -> str:
    cleaned = name.replace("\\", "_").replace("/", "_").strip()
    return cleaned or "attachment.bin"


@lru_cache(maxsize=1)
def get_audit_service() -> AuditService:
    settings = get_settings()
    audit_config = settings.get("audit", {})
    evidence_root = str(audit_config.get("evidence_root", "evidence"))
    write_index = bool(audit_config.get("write_index", True))
    return AuditService(
        evidence_root=evidence_root,
        write_index=write_index,
        redaction_settings=get_redaction_settings(),
    )


def clear_audit_service_cache() -> None:
    get_audit_service.cache_clear()
