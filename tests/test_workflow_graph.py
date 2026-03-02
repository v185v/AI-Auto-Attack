from agents.workflow_graph import run_poc_workflow
from backend.audit.service import AuditService
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
            "tool_results": [
                {
                    "tool": "nmap",
                    "status": "success",
                    "findings": [
                        {
                            "id": "nmap-open-port-80",
                            "severity": "medium",
                            "confidence": 0.9,
                            "evidence": "80/tcp http",
                        }
                    ],
                }
            ],
            "executed_tools": 1,
            "blocked_tools": 0,
            "failed_tools": 0,
            "skipped_tools": 0,
            "findings": [
                {
                    "id": "nmap-open-port-80",
                    "severity": "medium",
                    "confidence": 0.9,
                    "evidence": "80/tcp http",
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
            "risk_hypotheses": [
                {"hypothesis": "stub risk", "severity": "medium", "confidence": 0.8, "rationale": "stub evidence"}
            ],
            "next_actions": [
                {"action": "stub_action", "objective": "stub", "required_tool": "nmap", "risk_level": "low"}
            ],
            "evidence_interpretation": {
                "verified_signals": ["stub"],
                "uncertain_signals": [],
                "overall_decision": "risk_confirmed",
                "confidence": 0.8,
            },
            "summary": {"target": target, "finding_count": scan.get("finding_count", 0), "overall_decision": "risk_confirmed"},
        }


def test_poc_workflow_completed_for_in_scope_target(tmp_path) -> None:
    scope_guard = ScopeGuard(
        {
            "default_decision": "deny",
            "authorized_targets": {"cidr": ["10.20.0.0/16"]},
        }
    )
    audit_service = AuditService(evidence_root=str(tmp_path / "evidence"), write_index=True)

    report_generator = ReportGenerator(output_dir=str(tmp_path / "reports"), enable_pdf=False)
    result = run_poc_workflow(
        target="10.20.1.8",
        requested_by="tester",
        scope_guard=scope_guard,
        audit_service=audit_service,
        scan_orchestrator=StubScanOrchestrator(),
        decision_engine=StubDecisionEngine(),
        report_generator=report_generator,
        trace_id="trace-workflow-success",
        task_id="task-workflow-success",
    )

    assert result["status"] == "completed"
    assert result["report"]["status"] == "completed"
    assert result["analysis"]["allowed"] is True
    assert result["target_profile"]["target_type"] == "ip"
    assert result["target_profile"]["strategy_hint"] in {"strategy_generic", "strategy_linux", "strategy_windows"}
    assert result["llm_decision"]["mode"] == "stub"
    assert result["report"]["summary"]["target"] == "10.20.1.8"
    assert result["report_artifacts"]["json_path"]
    assert result["report_artifacts"]["markdown_path"]
    assert result["defectdojo_sync"]["status"] == "skipped"
    assert len(result["steps"]) >= 5
    assert len(result["audit_events"]) >= 5


def test_poc_workflow_failed_for_out_of_scope_target(tmp_path) -> None:
    scope_guard = ScopeGuard(
        {
            "default_decision": "deny",
            "authorized_targets": {"cidr": ["10.20.0.0/16"]},
        }
    )
    audit_service = AuditService(evidence_root=str(tmp_path / "evidence"), write_index=True)

    report_generator = ReportGenerator(output_dir=str(tmp_path / "reports"), enable_pdf=False)
    result = run_poc_workflow(
        target="192.168.1.88",
        requested_by="tester",
        scope_guard=scope_guard,
        audit_service=audit_service,
        scan_orchestrator=StubScanOrchestrator(),
        decision_engine=StubDecisionEngine(),
        report_generator=report_generator,
        trace_id="trace-workflow-fail",
        task_id="task-workflow-fail",
    )

    assert result["status"] == "failed"
    assert result["report"]["status"] == "failed"
    assert result["defectdojo_sync"]["status"] == "skipped"
    assert "scope_denied" in result["failure_reason"]
    assert "scope_denied" in result["report"]["summary"]["failure_reason"]
    assert len(result["audit_events"]) >= 2
