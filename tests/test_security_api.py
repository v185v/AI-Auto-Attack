from pathlib import Path
import json

from fastapi.testclient import TestClient

from backend.api.security import action_gate_dep, approval_store_dep, audit_service_dep, scope_guard_dep
from backend.audit.service import AuditService
from backend.main import app
from backend.security.action_gate import ActionGate
from backend.security.approval_store import ApprovalStore
from backend.security.scope_guard import ScopeGuard


def test_scope_and_action_interception_with_approval_flow(tmp_path) -> None:
    scope_policy = {
        "default_decision": "deny",
        "authorized_targets": {"cidr": ["10.20.0.0/16"]},
    }
    action_policy = {
        "command_allowlist": {
            "low_risk": ["nmap"],
            "medium_risk": [],
            "high_risk": ["msfconsole"],
        },
        "gates": {"require_approval_for_high_risk": True},
    }

    approval_store = ApprovalStore()
    guard = ScopeGuard(scope_policy)
    gate = ActionGate(policy=action_policy, approval_store=approval_store)
    audit_service = AuditService(evidence_root=str(tmp_path / "evidence"), write_index=True)

    app.dependency_overrides[scope_guard_dep] = lambda: guard
    app.dependency_overrides[action_gate_dep] = lambda: gate
    app.dependency_overrides[approval_store_dep] = lambda: approval_store
    app.dependency_overrides[audit_service_dep] = lambda: audit_service

    try:
        client = TestClient(app)
        executor_headers = {"X-Actor-Id": "tester", "X-Role": "executor"}
        admin_headers = {"X-Actor-Id": "sec-lead", "X-Role": "admin"}

        denied_scope = client.post(
            "/actions/validate",
            json={"target": "192.168.1.9", "command": "nmap -sV", "requested_by": "tester"},
            headers=executor_headers,
        )
        assert denied_scope.status_code == 403
        denied_detail = denied_scope.json()["detail"]
        assert denied_detail["reason"] in {"ip_out_of_scope", "target_out_of_scope"}
        _assert_evidence_files(denied_detail["evidence_dir"])

        blocked_high_risk = client.post(
            "/actions/validate",
            json={"target": "10.20.1.8", "command": "msfconsole -q", "requested_by": "spoofed-user"},
            headers=executor_headers,
        )
        assert blocked_high_risk.status_code == 409
        blocked_detail = blocked_high_risk.json()["detail"]
        assert blocked_detail["reason"] == "approval_required"
        _assert_evidence_files(blocked_detail["evidence_dir"])
        approval_id = blocked_detail["approval_id"]
        assert approval_id

        approval_record = client.get(
            f"/approvals/{approval_id}",
            headers=executor_headers,
        )
        assert approval_record.status_code == 200
        # requested_by should be bound to authenticated actor, not caller-supplied payload field.
        assert approval_record.json()["requested_by"] == "tester"

        forbidden_decision = client.post(
            f"/approvals/{approval_id}/decision",
            json={"status": "approved", "approver": "tester"},
            headers=executor_headers,
        )
        assert forbidden_decision.status_code == 403
        assert forbidden_decision.json()["detail"]["reason"] == "permission_denied"

        mismatch_decision = client.post(
            f"/approvals/{approval_id}/decision",
            json={"status": "approved", "approver": "someone-else"},
            headers=admin_headers,
        )
        assert mismatch_decision.status_code == 400
        assert mismatch_decision.json()["detail"]["reason"] == "approver_actor_mismatch"

        decision = client.post(
            f"/approvals/{approval_id}/decision",
            json={"status": "approved", "approver": "sec-lead", "trace_id": "trace-approval-decision"},
            headers=admin_headers,
        )
        assert decision.status_code == 200
        assert decision.json()["status"] == "approved"
        assert decision.json()["approver"] == "sec-lead"
        assert isinstance(decision.json().get("decision_signature"), str)
        assert len(decision.json().get("decision_signature", "")) == 64
        assert isinstance(decision.json().get("decision_history"), list)
        _assert_evidence_files(decision.json()["audit"]["evidence_dir"])

        repeated_decision = client.post(
            f"/approvals/{approval_id}/decision",
            json={"status": "rejected", "approver": "sec-lead", "trace_id": "trace-approval-decision"},
            headers=admin_headers,
        )
        assert repeated_decision.status_code == 200
        assert repeated_decision.json()["status"] == "approved"
        first_event = json.loads(
            (Path(decision.json()["audit"]["evidence_dir"]) / "event.json").read_text(encoding="utf-8")
        )
        repeated_event = json.loads(
            (Path(repeated_decision.json()["audit"]["evidence_dir"]) / "event.json").read_text(encoding="utf-8")
        )
        assert first_event["reason"] == "approval_state_updated"
        assert repeated_event["reason"] == "approval_state_unchanged"

        allowed = client.post(
            "/actions/validate",
            json={
                "target": "10.20.1.8",
                "command": "msfconsole -q",
                "requested_by": "tester",
                "approval_id": approval_id,
            },
            headers=executor_headers,
        )
        assert allowed.status_code == 200
        assert allowed.json()["allowed"] is True
        assert allowed.json()["action"]["reason"] == "approval_granted"
        _assert_evidence_files(allowed.json()["audit"]["evidence_dir"])
    finally:
        app.dependency_overrides.clear()


def _assert_evidence_files(evidence_dir: str) -> None:
    base = Path(evidence_dir)
    assert base.exists()
    assert (base / "event.json").exists()
    assert (base / "input.json").exists()
    assert (base / "output.json").exists()
