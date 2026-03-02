from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from agents.decision_engine import DecisionEngine
from agents.workflow_graph import replay_poc_workflow_from_task, resume_poc_workflow_from_task, run_retest_workflow_from_task
from backend.audit.service import AuditService
from backend.security.scope_guard import ScopeGuard
from backend.workflow.state_store import WorkflowStateStore, get_workflow_state_store
from connectors.defectdojo_connector import DefectDojoConnector
from connectors.scan_orchestrator import ScanOrchestrator
from reports.diff_generator import DiffReportGenerator
from reports.generator import ReportGenerator

from backend.api.workflows import (
    workflow_audit_service_dep,
    workflow_decision_engine_dep,
    workflow_defectdojo_dep,
    workflow_diff_report_generator_dep,
    workflow_report_generator_dep,
    workflow_scan_orchestrator_dep,
    workflow_scope_guard_dep,
)

router = APIRouter(prefix="/tasks", tags=["tasks"])


def task_state_store_dep() -> WorkflowStateStore:
    return get_workflow_state_store()


@router.get("/{task_id}/snapshots")
def list_task_snapshots(
    task_id: str,
    state_store: WorkflowStateStore = Depends(task_state_store_dep),
) -> dict:
    items = state_store.list_snapshots(task_id)
    if not items:
        raise HTTPException(status_code=404, detail={"reason": "task_not_found"})
    return {"task_id": task_id, "count": len(items), "items": items}


@router.get("/{task_id}/snapshots/{version}")
def get_task_snapshot(
    task_id: str,
    version: int,
    state_store: WorkflowStateStore = Depends(task_state_store_dep),
) -> dict:
    item = state_store.get_snapshot(task_id, version)
    if item is None:
        raise HTTPException(status_code=404, detail={"reason": "snapshot_not_found"})
    return item


@router.post("/{task_id}/resume")
def resume_task(
    task_id: str,
    scope_guard: ScopeGuard = Depends(workflow_scope_guard_dep),
    audit_service: AuditService = Depends(workflow_audit_service_dep),
    scan_orchestrator: ScanOrchestrator = Depends(workflow_scan_orchestrator_dep),
    decision_engine: DecisionEngine = Depends(workflow_decision_engine_dep),
    report_generator: ReportGenerator = Depends(workflow_report_generator_dep),
    defectdojo_connector: DefectDojoConnector = Depends(workflow_defectdojo_dep),
    state_store: WorkflowStateStore = Depends(task_state_store_dep),
) -> dict:
    try:
        result = resume_poc_workflow_from_task(
            task_id=task_id,
            scope_guard=scope_guard,
            audit_service=audit_service,
            scan_orchestrator=scan_orchestrator,
            decision_engine=decision_engine,
            report_generator=report_generator,
            defectdojo_connector=defectdojo_connector,
            state_store=state_store,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail={"reason": str(exc)}) from exc
    return result


@router.post("/{task_id}/replay")
def replay_task(
    task_id: str,
    scope_guard: ScopeGuard = Depends(workflow_scope_guard_dep),
    audit_service: AuditService = Depends(workflow_audit_service_dep),
    scan_orchestrator: ScanOrchestrator = Depends(workflow_scan_orchestrator_dep),
    decision_engine: DecisionEngine = Depends(workflow_decision_engine_dep),
    report_generator: ReportGenerator = Depends(workflow_report_generator_dep),
    defectdojo_connector: DefectDojoConnector = Depends(workflow_defectdojo_dep),
    state_store: WorkflowStateStore = Depends(task_state_store_dep),
) -> dict:
    try:
        result = replay_poc_workflow_from_task(
            task_id=task_id,
            scope_guard=scope_guard,
            audit_service=audit_service,
            scan_orchestrator=scan_orchestrator,
            decision_engine=decision_engine,
            report_generator=report_generator,
            defectdojo_connector=defectdojo_connector,
            state_store=state_store,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail={"reason": str(exc)}) from exc
    return result


@router.post("/{task_id}/retest")
def retest_task(
    task_id: str,
    scope_guard: ScopeGuard = Depends(workflow_scope_guard_dep),
    audit_service: AuditService = Depends(workflow_audit_service_dep),
    scan_orchestrator: ScanOrchestrator = Depends(workflow_scan_orchestrator_dep),
    decision_engine: DecisionEngine = Depends(workflow_decision_engine_dep),
    report_generator: ReportGenerator = Depends(workflow_report_generator_dep),
    defectdojo_connector: DefectDojoConnector = Depends(workflow_defectdojo_dep),
    diff_report_generator: DiffReportGenerator = Depends(workflow_diff_report_generator_dep),
    state_store: WorkflowStateStore = Depends(task_state_store_dep),
) -> dict:
    try:
        result = run_retest_workflow_from_task(
            task_id=task_id,
            scope_guard=scope_guard,
            audit_service=audit_service,
            scan_orchestrator=scan_orchestrator,
            decision_engine=decision_engine,
            report_generator=report_generator,
            defectdojo_connector=defectdojo_connector,
            diff_report_generator=diff_report_generator,
            state_store=state_store,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail={"reason": str(exc)}) from exc
    return result
