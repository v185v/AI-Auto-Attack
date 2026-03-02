from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from backend.api.audit import audit_service_dep, retention_service_dep
from backend.audit.retention import RetentionService, RetentionSettings
from backend.audit.models import create_audit_context
from backend.audit.service import AuditService
from backend.main import app


def test_query_audit_events_by_trace_id_and_task_id(tmp_path) -> None:
    audit_service = AuditService(evidence_root=str(tmp_path / "evidence"), write_index=True)

    context_a = create_audit_context(
        operator="tester-a",
        trace_id="trace-a",
        task_id="task-a",
        agent_id="agent-a",
    )
    context_b = create_audit_context(
        operator="tester-b",
        trace_id="trace-b",
        task_id="task-b",
        agent_id="agent-b",
    )
    audit_service.record_event(
        context=context_a,
        action="validate_action",
        target="10.0.0.1",
        tool="scope_guard",
        decision="blocked",
        reason="target_out_of_scope",
        input_payload={"target": "10.0.0.1"},
        output_payload={"allowed": False},
    )
    audit_service.record_event(
        context=context_a,
        action="validate_action",
        target="10.20.1.8",
        tool="action_gate",
        decision="pending_approval",
        reason="approval_required",
        input_payload={"target": "10.20.1.8"},
        output_payload={"allowed": False},
    )
    audit_service.record_event(
        context=context_b,
        action="approval_decision",
        target="10.20.1.8",
        tool="approval_gate",
        decision="approved",
        reason="approval_state_updated",
        input_payload={"status": "approved"},
        output_payload={"status": "approved"},
    )

    app.dependency_overrides[audit_service_dep] = lambda: audit_service
    try:
        client = TestClient(app)

        by_trace = client.get("/audit/events", params={"trace_id": "trace-a"})
        assert by_trace.status_code == 200
        body_trace = by_trace.json()
        assert body_trace["total"] == 2
        assert len(body_trace["items"]) == 2
        assert all(item["trace_id"] == "trace-a" for item in body_trace["items"])

        by_task = client.get("/audit/events", params={"task_id": "task-b"})
        assert by_task.status_code == 200
        body_task = by_task.json()
        assert body_task["total"] == 1
        assert body_task["items"][0]["task_id"] == "task-b"

        paged = client.get("/audit/events", params={"trace_id": "trace-a", "limit": 1, "offset": 1})
        assert paged.status_code == 200
        body_page = paged.json()
        assert body_page["total"] == 2
        assert body_page["limit"] == 1
        assert body_page["offset"] == 1
        assert len(body_page["items"]) == 1
    finally:
        app.dependency_overrides.clear()


def test_query_audit_events_requires_trace_or_task(tmp_path) -> None:
    audit_service = AuditService(evidence_root=str(tmp_path / "evidence"), write_index=True)
    app.dependency_overrides[audit_service_dep] = lambda: audit_service
    try:
        client = TestClient(app)
        response = client.get("/audit/events")
        assert response.status_code == 400
        assert response.json()["detail"]["reason"] == "trace_id_or_task_id_required"
    finally:
        app.dependency_overrides.clear()


def test_prune_audit_retention_requires_admin_role(tmp_path) -> None:
    evidence_root = tmp_path / "evidence"
    reports_root = tmp_path / "reports"
    diff_root = tmp_path / "diff"
    old_date = (datetime.now(UTC).date() - timedelta(days=30)).isoformat()
    for root in (evidence_root, reports_root, diff_root):
        path = root / old_date
        path.mkdir(parents=True, exist_ok=True)
        (path / "dummy.txt").write_text("x", encoding="utf-8")

    retention_service = RetentionService(
        RetentionSettings(
            enabled=True,
            evidence_days=7,
            reports_days=7,
            evidence_root=evidence_root.as_posix(),
            report_output_dir=reports_root.as_posix(),
            report_diff_output_dir=diff_root.as_posix(),
        )
    )
    app.dependency_overrides[retention_service_dep] = lambda: retention_service
    try:
        client = TestClient(app)

        forbidden = client.post(
            "/audit/retention/prune",
            params={"dry_run": "true"},
            headers={"X-Actor-Id": "op-1", "X-Role": "executor"},
        )
        assert forbidden.status_code == 403
        assert forbidden.json()["detail"]["reason"] == "permission_denied"

        allowed = client.post(
            "/audit/retention/prune",
            params={"dry_run": "true"},
            headers={"X-Actor-Id": "sec-admin", "X-Role": "admin"},
        )
        assert allowed.status_code == 200
        payload = allowed.json()
        assert payload["status"] == "completed"
        assert payload["dry_run"] is True
        assert payload["requested_by"] == "sec-admin"
        assert payload["evidence"]["pruned_count"] == 1
        assert payload["reports"]["pruned_count"] == 1
        assert payload["diff_reports"]["pruned_count"] == 1
    finally:
        app.dependency_overrides.clear()
