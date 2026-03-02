from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from agents.decision_engine import DecisionEngine, get_decision_engine
from agents.multi_stage_workflow import run_multi_stage_workflow
from agents.workflow_graph import run_poc_workflow
from backend.audit.service import AuditService, get_audit_service
from backend.scheduler.resource_quota import ResourceQuotaManager, get_resource_quota_manager
from backend.security.scope_guard import ScopeGuard, get_scope_guard
from backend.workflow.temporal_worker import (
    TemporalSettings,
    TemporalWorkflowClient,
    get_temporal_settings,
    get_temporal_workflow_client,
)
from backend.workflow.state_store import WorkflowStateStore, get_workflow_state_store
from connectors.defectdojo_connector import DefectDojoConnector, get_defectdojo_connector
from connectors.scan_orchestrator import ScanOrchestrator, get_scan_orchestrator
from reports.diff_generator import DiffReportGenerator, get_diff_report_generator
from reports.generator import ReportGenerator, get_report_generator
from reports.path_view_generator import PathViewGenerator, get_path_view_generator

router = APIRouter(prefix="/workflows", tags=["workflows"])


class RunPocWorkflowRequest(BaseModel):
    target: str = Field(..., min_length=1)
    requested_by: str = Field(default="system", min_length=1)
    trace_id: str | None = None
    task_id: str | None = None
    agent_id: str = Field(default="workflow-p1", min_length=1)


class StartPocWorkflowRequest(RunPocWorkflowRequest):
    workflow_id: str | None = None


class MultiStageNodeRequest(BaseModel):
    id: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    depends_on: list[str] = Field(default_factory=list)
    requested_by: str | None = None
    priority: int = Field(default=100, ge=1, le=1000)


class RunMultiStageWorkflowRequest(BaseModel):
    nodes: list[MultiStageNodeRequest]
    requested_by: str = Field(default="system", min_length=1)
    continue_on_error: bool = False
    requested_parallelism: int = Field(default=1, ge=1, le=32)
    trace_id: str | None = None
    task_id_prefix: str | None = None
    agent_id: str = Field(default="workflow-p6-multi-stage", min_length=1)


def workflow_scope_guard_dep() -> ScopeGuard:
    return get_scope_guard()


def workflow_audit_service_dep() -> AuditService:
    return get_audit_service()


def workflow_scan_orchestrator_dep() -> ScanOrchestrator:
    return get_scan_orchestrator()


def workflow_decision_engine_dep() -> DecisionEngine:
    return get_decision_engine()


def workflow_report_generator_dep() -> ReportGenerator:
    return get_report_generator()


def workflow_diff_report_generator_dep() -> DiffReportGenerator:
    return get_diff_report_generator()


def workflow_defectdojo_dep() -> DefectDojoConnector:
    return get_defectdojo_connector()


def workflow_temporal_settings_dep() -> TemporalSettings:
    return get_temporal_settings()


def workflow_temporal_client_dep() -> TemporalWorkflowClient:
    return get_temporal_workflow_client()


def workflow_state_store_dep() -> WorkflowStateStore:
    return get_workflow_state_store()


def workflow_resource_quota_dep() -> ResourceQuotaManager:
    return get_resource_quota_manager()


def workflow_path_view_generator_dep() -> PathViewGenerator:
    return get_path_view_generator()


@router.post("/poc/run")
def run_poc_single_target_workflow(
    payload: RunPocWorkflowRequest,
    scope_guard: ScopeGuard = Depends(workflow_scope_guard_dep),
    audit_service: AuditService = Depends(workflow_audit_service_dep),
    scan_orchestrator: ScanOrchestrator = Depends(workflow_scan_orchestrator_dep),
    decision_engine: DecisionEngine = Depends(workflow_decision_engine_dep),
    report_generator: ReportGenerator = Depends(workflow_report_generator_dep),
    defectdojo_connector: DefectDojoConnector = Depends(workflow_defectdojo_dep),
    state_store: WorkflowStateStore = Depends(workflow_state_store_dep),
) -> dict:
    result = run_poc_workflow(
        target=payload.target,
        requested_by=payload.requested_by,
        trace_id=payload.trace_id,
        task_id=payload.task_id,
        agent_id=payload.agent_id,
        scope_guard=scope_guard,
        audit_service=audit_service,
        scan_orchestrator=scan_orchestrator,
        decision_engine=decision_engine,
        report_generator=report_generator,
        defectdojo_connector=defectdojo_connector,
        state_store=state_store,
    )
    return result


@router.post("/multi-stage/run")
def run_multi_stage_workflow_api(
    payload: RunMultiStageWorkflowRequest,
    scope_guard: ScopeGuard = Depends(workflow_scope_guard_dep),
    audit_service: AuditService = Depends(workflow_audit_service_dep),
    scan_orchestrator: ScanOrchestrator = Depends(workflow_scan_orchestrator_dep),
    decision_engine: DecisionEngine = Depends(workflow_decision_engine_dep),
    report_generator: ReportGenerator = Depends(workflow_report_generator_dep),
    defectdojo_connector: DefectDojoConnector = Depends(workflow_defectdojo_dep),
    resource_quota: ResourceQuotaManager = Depends(workflow_resource_quota_dep),
    path_view_generator: PathViewGenerator = Depends(workflow_path_view_generator_dep),
) -> dict:
    try:
        return run_multi_stage_workflow(
            nodes=[item.model_dump() for item in payload.nodes],
            requested_by=payload.requested_by,
            continue_on_error=payload.continue_on_error,
            requested_parallelism=payload.requested_parallelism,
            trace_id=payload.trace_id,
            task_id_prefix=payload.task_id_prefix,
            agent_id=payload.agent_id,
            scope_guard=scope_guard,
            audit_service=audit_service,
            scan_orchestrator=scan_orchestrator,
            decision_engine=decision_engine,
            report_generator=report_generator,
            defectdojo_connector=defectdojo_connector,
            resource_quota=resource_quota,
            path_view_generator=path_view_generator,
        )
    except ValueError as exc:
        reason = str(exc)
        status_code = 409 if reason.startswith("quota_rejected:") else 400
        raise HTTPException(status_code=status_code, detail={"reason": reason}) from exc


@router.post("/poc/start")
async def start_poc_single_target_workflow(
    payload: StartPocWorkflowRequest,
    temporal_settings: TemporalSettings = Depends(workflow_temporal_settings_dep),
    temporal_client: TemporalWorkflowClient = Depends(workflow_temporal_client_dep),
) -> dict:
    if not temporal_settings.enabled:
        raise HTTPException(
            status_code=503,
            detail={"reason": "temporal_disabled", "hint": "enable workflow.temporal.enabled in settings.yaml"},
        )
    start_payload = payload.model_dump(exclude={"workflow_id"})
    return await temporal_client.start_poc_workflow(start_payload, workflow_id=payload.workflow_id)


@router.get("/poc/status/{workflow_id}")
async def get_poc_workflow_status(
    workflow_id: str,
    run_id: str | None = None,
    temporal_settings: TemporalSettings = Depends(workflow_temporal_settings_dep),
    temporal_client: TemporalWorkflowClient = Depends(workflow_temporal_client_dep),
) -> dict:
    if not temporal_settings.enabled:
        raise HTTPException(status_code=503, detail={"reason": "temporal_disabled"})
    return await temporal_client.describe_workflow(workflow_id=workflow_id, run_id=run_id)


@router.get("/poc/result/{workflow_id}")
async def get_poc_workflow_result(
    workflow_id: str,
    run_id: str | None = None,
    temporal_settings: TemporalSettings = Depends(workflow_temporal_settings_dep),
    temporal_client: TemporalWorkflowClient = Depends(workflow_temporal_client_dep),
) -> dict:
    if not temporal_settings.enabled:
        raise HTTPException(status_code=503, detail={"reason": "temporal_disabled"})
    return await temporal_client.get_result(workflow_id=workflow_id, run_id=run_id)


@router.post("/poc/cancel/{workflow_id}")
async def cancel_poc_workflow(
    workflow_id: str,
    run_id: str | None = None,
    temporal_settings: TemporalSettings = Depends(workflow_temporal_settings_dep),
    temporal_client: TemporalWorkflowClient = Depends(workflow_temporal_client_dep),
) -> dict:
    if not temporal_settings.enabled:
        raise HTTPException(status_code=503, detail={"reason": "temporal_disabled"})
    return await temporal_client.cancel_workflow(workflow_id=workflow_id, run_id=run_id)
