from fastapi.testclient import TestClient

from backend.api.workflows import (
    workflow_audit_service_dep,
    workflow_decision_engine_dep,
    workflow_report_generator_dep,
    workflow_scan_orchestrator_dep,
    workflow_scope_guard_dep,
)
from backend.audit.service import AuditService
from backend.main import app
from backend.security.scope_guard import ScopeGuard
from reports.generator import ReportGenerator


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
        return {
            "status": "completed",
            "failure_reason": "",
            "target": target,
            "strategy": {
                "key": strategy_hint or "strategy_generic",
                "name": "stub",
                "enabled_tools": ["nmap"],
            },
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
            "target_profile": {"os_guess": "unknown", "exposed_services": [], "attack_surface_summary": "stub"},
            "risk_hypotheses": [],
            "next_actions": [],
            "evidence_interpretation": {
                "verified_signals": [],
                "uncertain_signals": [],
                "overall_decision": "no_confirmed_risk",
                "confidence": 0.5,
            },
            "summary": {"target": target, "finding_count": scan.get("finding_count", 0), "overall_decision": "no_confirmed_risk"},
        }


def test_workflow_api_returns_completed_and_failed_states(tmp_path) -> None:
    scope_guard = ScopeGuard(
        {
            "default_decision": "deny",
            "authorized_targets": {"cidr": ["10.20.0.0/16"]},
        }
    )
    audit_service = AuditService(evidence_root=str(tmp_path / "evidence"), write_index=True)
    report_generator = ReportGenerator(output_dir=str(tmp_path / "reports"), enable_pdf=False)

    app.dependency_overrides[workflow_scope_guard_dep] = lambda: scope_guard
    app.dependency_overrides[workflow_audit_service_dep] = lambda: audit_service
    app.dependency_overrides[workflow_scan_orchestrator_dep] = lambda: StubScanOrchestrator()
    app.dependency_overrides[workflow_decision_engine_dep] = lambda: StubDecisionEngine()
    app.dependency_overrides[workflow_report_generator_dep] = lambda: report_generator
    try:
        client = TestClient(app)

        completed = client.post(
            "/workflows/poc/run",
            json={"target": "10.20.1.8", "requested_by": "tester"},
        )
        assert completed.status_code == 200
        body_completed = completed.json()
        assert body_completed["status"] == "completed"
        assert body_completed["target_profile"]["target_type"] == "ip"
        assert body_completed["scan"]["strategy"]["key"] in {"strategy_generic", "strategy_linux", "strategy_windows"}
        assert body_completed["report"]["status"] == "completed"
        assert body_completed["defectdojo_sync"]["status"] == "skipped"
        assert body_completed["llm_decision"]["mode"] == "stub"
        assert body_completed["report_artifacts"]["json_path"]

        failed = client.post(
            "/workflows/poc/run",
            json={"target": "172.16.10.8", "requested_by": "tester"},
        )
        assert failed.status_code == 200
        body_failed = failed.json()
        assert body_failed["status"] == "failed"
        assert "scope_denied" in body_failed["failure_reason"]
    finally:
        app.dependency_overrides.clear()
