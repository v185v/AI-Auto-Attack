from fastapi.testclient import TestClient

from backend.api.tasks import task_state_store_dep
from backend.api.workflows import (
    workflow_audit_service_dep,
    workflow_decision_engine_dep,
    workflow_report_generator_dep,
    workflow_scan_orchestrator_dep,
    workflow_scope_guard_dep,
    workflow_state_store_dep,
)
from backend.audit.service import AuditService
from backend.main import app
from backend.security.scope_guard import ScopeGuard
from backend.workflow.state_store import StateStoreSettings, WorkflowStateStore
from reports.generator import ReportGenerator


class FailingScanOrchestrator:
    def execute(
        self,
        *,
        target: str,
        requested_by: str,
        strategy_hint: str | None = None,
        target_profile: dict | None = None,
        force_tools: list[str] | None = None,
    ) -> dict:
        return {
            "status": "failed",
            "failure_reason": "all_tools_failed",
            "target": target,
            "strategy": {"key": strategy_hint or "strategy_generic", "name": "stub", "enabled_tools": ["nmap"]},
            "tool_results": [],
            "executed_tools": 1,
            "blocked_tools": 0,
            "failed_tools": 1,
            "skipped_tools": 0,
            "findings": [],
            "finding_count": 0,
        }


class SuccessfulScanOrchestrator:
    def execute(
        self,
        *,
        target: str,
        requested_by: str,
        strategy_hint: str | None = None,
        target_profile: dict | None = None,
        force_tools: list[str] | None = None,
    ) -> dict:
        return {
            "status": "completed",
            "failure_reason": "",
            "target": target,
            "strategy": {"key": strategy_hint or "strategy_generic", "name": "stub", "enabled_tools": ["nmap"]},
            "tool_results": [],
            "executed_tools": 1,
            "blocked_tools": 0,
            "failed_tools": 0,
            "skipped_tools": 0,
            "findings": [
                {
                    "id": "finding-1",
                    "type": "open_port",
                    "severity": "medium",
                    "confidence": 0.9,
                    "evidence": "80/tcp",
                    "details": {"service": "http"},
                }
            ],
            "finding_count": 1,
        }


class NoFindingScanOrchestrator:
    def execute(
        self,
        *,
        target: str,
        requested_by: str,
        strategy_hint: str | None = None,
        target_profile: dict | None = None,
        force_tools: list[str] | None = None,
    ) -> dict:
        return {
            "status": "completed",
            "failure_reason": "",
            "target": target,
            "strategy": {"key": strategy_hint or "strategy_generic", "name": "stub", "enabled_tools": force_tools or ["nmap"]},
            "tool_results": [],
            "executed_tools": 1,
            "blocked_tools": 0,
            "failed_tools": 0,
            "skipped_tools": 0,
            "findings": [],
            "finding_count": 0,
        }


class StubDecisionEngine:
    def decide(self, *, target: str, analysis: dict, scan: dict) -> dict:
        return {
            "mode": "stub",
            "model": "stub-model",
            "target_profile": {"os_guess": "unknown", "exposed_services": ["http"], "attack_surface_summary": "stub"},
            "risk_hypotheses": [],
            "next_actions": [],
            "evidence_interpretation": {
                "verified_signals": [],
                "uncertain_signals": [],
                "overall_decision": "risk_confirmed",
                "confidence": 0.8,
            },
            "summary": {"target": target, "finding_count": scan.get("finding_count", 0), "overall_decision": "risk_confirmed"},
        }


def test_tasks_resume_and_replay_from_state_store(tmp_path) -> None:
    scope_guard = ScopeGuard(
        {
            "default_decision": "deny",
            "authorized_targets": {"cidr": ["10.20.0.0/16"]},
        }
    )
    audit_service = AuditService(evidence_root=str(tmp_path / "evidence"), write_index=True)
    report_generator = ReportGenerator(output_dir=str(tmp_path / "reports"), enable_pdf=False)
    state_store = WorkflowStateStore(StateStoreSettings(directory=str(tmp_path / "state")))

    app.dependency_overrides[workflow_scope_guard_dep] = lambda: scope_guard
    app.dependency_overrides[workflow_audit_service_dep] = lambda: audit_service
    app.dependency_overrides[workflow_scan_orchestrator_dep] = lambda: FailingScanOrchestrator()
    app.dependency_overrides[workflow_decision_engine_dep] = lambda: StubDecisionEngine()
    app.dependency_overrides[workflow_report_generator_dep] = lambda: report_generator
    app.dependency_overrides[workflow_state_store_dep] = lambda: state_store
    app.dependency_overrides[task_state_store_dep] = lambda: state_store

    try:
        client = TestClient(app)
        run_resp = client.post(
            "/workflows/poc/run",
            json={"target": "10.20.1.8", "requested_by": "tester", "task_id": "task-resume-1", "trace_id": "trace-resume-1"},
        )
        assert run_resp.status_code == 200
        assert run_resp.json()["status"] == "failed"

        snapshots_resp = client.get("/tasks/task-resume-1/snapshots")
        assert snapshots_resp.status_code == 200
        assert snapshots_resp.json()["count"] >= 2

        app.dependency_overrides[workflow_scan_orchestrator_dep] = lambda: SuccessfulScanOrchestrator()

        resume_resp = client.post("/tasks/task-resume-1/resume")
        assert resume_resp.status_code == 200
        assert resume_resp.json()["status"] == "completed"
        assert resume_resp.json()["report"]["summary"]["failure_reason"] == ""
        assert int(resume_resp.json().get("state_version", 0)) > 0

        replay_resp = client.post("/tasks/task-resume-1/replay")
        assert replay_resp.status_code == 200
        assert replay_resp.json()["status"] == "completed"

        app.dependency_overrides[workflow_scan_orchestrator_dep] = lambda: NoFindingScanOrchestrator()
        retest_resp = client.post("/tasks/task-resume-1/retest")
        assert retest_resp.status_code == 200
        retest_body = retest_resp.json()
        assert retest_body["status"] == "completed"
        assert retest_body["retest_context"]["source_task_id"] == "task-resume-1"
        assert retest_body["source_task_id"] == "task-resume-1"
        assert retest_body["retest_task_id"] == retest_body["task_id"]
        assert retest_body["diff_report"]["summary"]["resolved_count"] >= 1
        assert retest_body["diff_report"]["summary"]["new_count"] == 0
        assert retest_body["task_id"] != "task-resume-1"
    finally:
        app.dependency_overrides.clear()
