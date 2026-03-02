from fastapi.testclient import TestClient
from pathlib import Path
from threading import Lock
import time

from backend.api.workflows import (
    workflow_audit_service_dep,
    workflow_decision_engine_dep,
    workflow_defectdojo_dep,
    workflow_path_view_generator_dep,
    workflow_report_generator_dep,
    workflow_resource_quota_dep,
    workflow_scan_orchestrator_dep,
    workflow_scope_guard_dep,
)
from backend.audit.service import AuditService
from backend.main import app
from backend.scheduler.resource_quota import ResourceQuotaManager, ResourceQuotaSettings
from backend.security.scope_guard import ScopeGuard
from reports.generator import ReportGenerator
from reports.path_view_generator import PathViewGenerator


class StubScanOrchestrator:
    def execute(
        self,
        *,
        target: str,
        requested_by: str,
        strategy_hint: str | None = None,
        target_profile: dict | None = None,
        force_tools: list[str] | None = None,
    ) -> dict:
        if target.endswith(".99"):
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
                    "id": f"finding-{target}",
                    "type": "open_port",
                    "severity": "medium",
                    "confidence": 0.9,
                    "evidence": "80/tcp",
                    "details": {"service": "http"},
                }
            ],
            "finding_count": 1,
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


class StubDefectDojoConnector:
    def upload_report(self, *, report, report_artifacts, task_id="", trace_id="", scan_name="") -> dict:
        return {"enabled": False, "status": "skipped", "reason": "defectdojo_disabled"}


class ConcurrentStubScanOrchestrator:
    def __init__(self, sleep_seconds: float = 0.15) -> None:
        self.sleep_seconds = sleep_seconds
        self._lock = Lock()
        self._current = 0
        self.max_inflight = 0

    def execute(
        self,
        *,
        target: str,
        requested_by: str,
        strategy_hint: str | None = None,
        target_profile: dict | None = None,
        force_tools: list[str] | None = None,
    ) -> dict:
        with self._lock:
            self._current += 1
            self.max_inflight = max(self.max_inflight, self._current)
        try:
            time.sleep(self.sleep_seconds)
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
                        "id": f"finding-{target}",
                        "type": "open_port",
                        "severity": "medium",
                        "confidence": 0.9,
                        "evidence": "80/tcp",
                        "details": {"service": "http"},
                    }
                ],
                "finding_count": 1,
            }
        finally:
            with self._lock:
                self._current -= 1


def test_multi_stage_workflow_api_executes_dependency_plan(tmp_path) -> None:
    scope_guard = ScopeGuard(
        {
            "default_decision": "deny",
            "authorized_targets": {"cidr": ["10.20.0.0/16"], "api_base_urls": ["http://10.20.1.8"]},
        }
    )
    audit_service = AuditService(evidence_root=str(tmp_path / "evidence"), write_index=True)
    report_generator = ReportGenerator(output_dir=str(tmp_path / "reports"), enable_pdf=False)
    path_view_generator = PathViewGenerator(output_dir=str(tmp_path / "path"))
    quota = ResourceQuotaManager(
        ResourceQuotaSettings(enabled=True, max_parallel_tasks=2, max_targets_per_run=10)
    )

    app.dependency_overrides[workflow_scope_guard_dep] = lambda: scope_guard
    app.dependency_overrides[workflow_audit_service_dep] = lambda: audit_service
    app.dependency_overrides[workflow_scan_orchestrator_dep] = lambda: StubScanOrchestrator()
    app.dependency_overrides[workflow_decision_engine_dep] = lambda: StubDecisionEngine()
    app.dependency_overrides[workflow_report_generator_dep] = lambda: report_generator
    app.dependency_overrides[workflow_path_view_generator_dep] = lambda: path_view_generator
    app.dependency_overrides[workflow_defectdojo_dep] = lambda: StubDefectDojoConnector()
    app.dependency_overrides[workflow_resource_quota_dep] = lambda: quota
    try:
        client = TestClient(app)
        response = client.post(
            "/workflows/multi-stage/run",
            json={
                "requested_by": "tester",
                "requested_parallelism": 2,
                "nodes": [
                    {"id": "node-a", "target": "10.20.1.8", "depends_on": []},
                    {"id": "node-b", "target": "10.20.1.9", "depends_on": ["node-a"]},
                ],
            },
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["status"] == "completed"
        assert payload["summary"]["total_nodes"] == 2
        assert payload["summary"]["failed_nodes"] == 0
        assert payload["execution_order"][0] == "node-a"
        assert payload["nodes"][0]["status"] == "completed"
        assert payload["nodes"][1]["status"] == "completed"
        assert payload["path_graph"]["summary"]["total_nodes"] == 2
        assert payload["path_graph"]["summary"]["total_paths"] >= 1
        assert payload["path_view"]["summary"]["total_nodes"] == 2
        assert Path(payload["path_artifacts"]["json_path"]).exists()
        assert Path(payload["path_artifacts"]["markdown_path"]).exists()
    finally:
        app.dependency_overrides.clear()


def test_multi_stage_workflow_api_skips_dependent_node_on_failure(tmp_path) -> None:
    scope_guard = ScopeGuard(
        {
            "default_decision": "deny",
            "authorized_targets": {"cidr": ["10.20.0.0/16"]},
        }
    )
    audit_service = AuditService(evidence_root=str(tmp_path / "evidence"), write_index=True)
    report_generator = ReportGenerator(output_dir=str(tmp_path / "reports"), enable_pdf=False)
    path_view_generator = PathViewGenerator(output_dir=str(tmp_path / "path"))
    quota = ResourceQuotaManager(
        ResourceQuotaSettings(enabled=True, max_parallel_tasks=2, max_targets_per_run=10)
    )

    app.dependency_overrides[workflow_scope_guard_dep] = lambda: scope_guard
    app.dependency_overrides[workflow_audit_service_dep] = lambda: audit_service
    app.dependency_overrides[workflow_scan_orchestrator_dep] = lambda: StubScanOrchestrator()
    app.dependency_overrides[workflow_decision_engine_dep] = lambda: StubDecisionEngine()
    app.dependency_overrides[workflow_report_generator_dep] = lambda: report_generator
    app.dependency_overrides[workflow_path_view_generator_dep] = lambda: path_view_generator
    app.dependency_overrides[workflow_defectdojo_dep] = lambda: StubDefectDojoConnector()
    app.dependency_overrides[workflow_resource_quota_dep] = lambda: quota
    try:
        client = TestClient(app)
        response = client.post(
            "/workflows/multi-stage/run",
            json={
                "requested_by": "tester",
                "requested_parallelism": 2,
                "nodes": [
                    {"id": "node-a", "target": "10.20.1.99", "depends_on": []},
                    {"id": "node-b", "target": "10.20.1.9", "depends_on": ["node-a"]},
                ],
            },
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["status"] == "failed"
        assert payload["summary"]["failed_nodes"] == 1
        assert payload["summary"]["skipped_nodes"] == 1
        node_status = {item["id"]: item["status"] for item in payload["nodes"]}
        assert node_status["node-a"] == "failed"
        assert node_status["node-b"] == "skipped"
        assert payload["path_graph"]["summary"]["total_nodes"] == 2
        assert Path(payload["path_artifacts"]["json_path"]).exists()
    finally:
        app.dependency_overrides.clear()


def test_multi_stage_workflow_api_rejects_quota_violation(tmp_path) -> None:
    scope_guard = ScopeGuard(
        {
            "default_decision": "deny",
            "authorized_targets": {"cidr": ["10.20.0.0/16"]},
        }
    )
    audit_service = AuditService(evidence_root=str(tmp_path / "evidence"), write_index=True)
    report_generator = ReportGenerator(output_dir=str(tmp_path / "reports"), enable_pdf=False)
    path_view_generator = PathViewGenerator(output_dir=str(tmp_path / "path"))
    quota = ResourceQuotaManager(
        ResourceQuotaSettings(enabled=True, max_parallel_tasks=2, max_targets_per_run=1)
    )

    app.dependency_overrides[workflow_scope_guard_dep] = lambda: scope_guard
    app.dependency_overrides[workflow_audit_service_dep] = lambda: audit_service
    app.dependency_overrides[workflow_scan_orchestrator_dep] = lambda: StubScanOrchestrator()
    app.dependency_overrides[workflow_decision_engine_dep] = lambda: StubDecisionEngine()
    app.dependency_overrides[workflow_report_generator_dep] = lambda: report_generator
    app.dependency_overrides[workflow_path_view_generator_dep] = lambda: path_view_generator
    app.dependency_overrides[workflow_defectdojo_dep] = lambda: StubDefectDojoConnector()
    app.dependency_overrides[workflow_resource_quota_dep] = lambda: quota
    try:
        client = TestClient(app)
        response = client.post(
            "/workflows/multi-stage/run",
            json={
                "requested_by": "tester",
                "nodes": [
                    {"id": "node-a", "target": "10.20.1.8", "depends_on": []},
                    {"id": "node-b", "target": "10.20.1.9", "depends_on": []},
                ],
            },
        )
        assert response.status_code == 409
        assert response.json()["detail"]["reason"].startswith("quota_rejected:")
    finally:
        app.dependency_overrides.clear()


def test_multi_stage_workflow_api_runs_ready_nodes_in_parallel(tmp_path) -> None:
    scope_guard = ScopeGuard(
        {
            "default_decision": "deny",
            "authorized_targets": {"cidr": ["10.20.0.0/16"]},
        }
    )
    audit_service = AuditService(evidence_root=str(tmp_path / "evidence"), write_index=True)
    report_generator = ReportGenerator(output_dir=str(tmp_path / "reports"), enable_pdf=False)
    path_view_generator = PathViewGenerator(output_dir=str(tmp_path / "path"))
    quota = ResourceQuotaManager(
        ResourceQuotaSettings(enabled=True, max_parallel_tasks=3, max_targets_per_run=10)
    )
    orchestrator = ConcurrentStubScanOrchestrator(sleep_seconds=0.2)

    app.dependency_overrides[workflow_scope_guard_dep] = lambda: scope_guard
    app.dependency_overrides[workflow_audit_service_dep] = lambda: audit_service
    app.dependency_overrides[workflow_scan_orchestrator_dep] = lambda: orchestrator
    app.dependency_overrides[workflow_decision_engine_dep] = lambda: StubDecisionEngine()
    app.dependency_overrides[workflow_report_generator_dep] = lambda: report_generator
    app.dependency_overrides[workflow_path_view_generator_dep] = lambda: path_view_generator
    app.dependency_overrides[workflow_defectdojo_dep] = lambda: StubDefectDojoConnector()
    app.dependency_overrides[workflow_resource_quota_dep] = lambda: quota
    try:
        client = TestClient(app)
        response = client.post(
            "/workflows/multi-stage/run",
            json={
                "requested_by": "tester",
                "requested_parallelism": 3,
                "nodes": [
                    {"id": "node-a", "target": "10.20.1.8", "depends_on": []},
                    {"id": "node-b", "target": "10.20.1.9", "depends_on": []},
                    {"id": "node-c", "target": "10.20.1.10", "depends_on": []},
                ],
            },
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["status"] == "completed"
        assert payload["summary"]["completed_nodes"] == 3
        assert orchestrator.max_inflight >= 2
    finally:
        app.dependency_overrides.clear()
