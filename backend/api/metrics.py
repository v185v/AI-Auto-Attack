from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from backend.observability.kpi_jobs import KPIJobService, get_kpi_job_service
from backend.observability.metrics import (
    WorkflowMetricsService,
    get_workflow_metrics_service,
)

router = APIRouter(prefix="/metrics", tags=["metrics"])


def workflow_metrics_dep() -> WorkflowMetricsService:
    return get_workflow_metrics_service()


def kpi_job_dep() -> KPIJobService:
    return get_kpi_job_service()


@router.get("/workflows/summary")
def get_workflow_metrics_summary(
    window_hours: int | None = Query(default=None, ge=1, le=24 * 90),
    metrics: WorkflowMetricsService = Depends(workflow_metrics_dep),
) -> dict:
    return metrics.summarize(window_hours=window_hours)


@router.get("/workflows/failures")
def get_workflow_failures(
    window_hours: int | None = Query(default=None, ge=1, le=24 * 90),
    limit: int = Query(default=50, ge=1, le=500),
    metrics: WorkflowMetricsService = Depends(workflow_metrics_dep),
) -> dict:
    return metrics.list_failures(window_hours=window_hours, limit=limit)


@router.get("/workflows/cost")
def get_workflow_cost_metrics(
    window_hours: int | None = Query(default=None, ge=1, le=24 * 90),
    metrics: WorkflowMetricsService = Depends(workflow_metrics_dep),
) -> dict:
    return metrics.summarize_cost(window_hours=window_hours)


@router.get("/kpi/summary")
def get_kpi_summary(
    period: str = Query(default="weekly", pattern="^(weekly|monthly)$"),
    service: KPIJobService = Depends(kpi_job_dep),
) -> dict:
    return service.generate_summary(period=period)  # type: ignore[arg-type]


@router.post("/kpi/export")
def export_kpi_summary(
    period: str = Query(default="weekly", pattern="^(weekly|monthly)$"),
    service: KPIJobService = Depends(kpi_job_dep),
) -> dict:
    return service.export_summary(period=period)  # type: ignore[arg-type]
