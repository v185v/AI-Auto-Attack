import json
from pathlib import Path

from backend.audit.models import create_audit_context
from backend.audit.service import AuditService


def test_audit_service_persists_event_and_hashes(tmp_path) -> None:
    service = AuditService(evidence_root=str(tmp_path / "evidence"), write_index=True)
    context = create_audit_context(
        operator="tester",
        trace_id="trace-123",
        task_id="task-123",
        agent_id="agent-1",
    )

    event = service.record_event(
        context=context,
        action="validate_action",
        target="10.20.1.8",
        tool="nmap",
        decision="allowed",
        reason="action_allowed",
        input_payload={"target": "10.20.1.8", "command": "nmap -sV", "api_token": "token-123"},
        output_payload={"allowed": True, "access_token": "output-token"},
        metadata={"password": "super-secret"},
        raw_output="Authorization: Bearer super-token",
        attachments={"scanner.log": "secret=attach-token"},
    )

    evidence_dir = Path(event.evidence_dir)
    event_json = json.loads((evidence_dir / "event.json").read_text(encoding="utf-8"))
    input_json = json.loads((evidence_dir / "input.json").read_text(encoding="utf-8"))
    output_json = json.loads((evidence_dir / "output.json").read_text(encoding="utf-8"))
    raw_output = (evidence_dir / "raw_output.txt").read_text(encoding="utf-8")
    attachment_text = (evidence_dir / "attachments" / "scanner.log").read_text(encoding="utf-8")

    assert event_json["trace_id"] == "trace-123"
    assert event_json["task_id"] == "task-123"
    assert event_json["operator"] == "tester"
    assert len(event_json["input_hash"]) == 64
    assert len(event_json["output_hash"]) == 64
    assert input_json["target"] == "10.20.1.8"
    assert input_json["api_token"] == "***REDACTED***"
    assert output_json["allowed"] is True
    assert output_json["access_token"] == "***REDACTED***"
    assert event_json["metadata"]["password"] == "***REDACTED***"
    assert "super-token" not in raw_output
    assert "***REDACTED***" in raw_output
    assert "attach-token" not in attachment_text
    assert (evidence_dir / "raw_output.txt").exists()
    assert (tmp_path / "evidence" / "audit-events.jsonl").exists()
