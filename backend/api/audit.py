from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.audit.retention import RetentionService, get_retention_service
from backend.audit.service import AuditService, get_audit_service
from backend.auth.rbac import Actor, get_actor, require_permission

router = APIRouter(prefix="/audit", tags=["audit"])


def audit_service_dep() -> AuditService:
    return get_audit_service()


def retention_service_dep() -> RetentionService:
    return get_retention_service()


def actor_dep(actor: Actor = Depends(get_actor)) -> Actor:
    return actor


@router.get("/events")
def query_audit_events(
    trace_id: str | None = Query(default=None),
    task_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    audit_service: AuditService = Depends(audit_service_dep),
) -> dict:
    if not trace_id and not task_id:
        raise HTTPException(
            status_code=400,
            detail={"reason": "trace_id_or_task_id_required"},
        )

    result = audit_service.query_events(
        trace_id=trace_id,
        task_id=task_id,
        limit=limit,
        offset=offset,
    )
    result["filters"] = {"trace_id": trace_id, "task_id": task_id}
    return result


@router.post("/retention/prune")
def prune_audit_retention(
    dry_run: bool = Query(default=True),
    retention_service: RetentionService = Depends(retention_service_dep),
    actor: Actor = Depends(actor_dep),
) -> dict:
    require_permission(actor, "retention:prune")
    result = retention_service.prune(dry_run=dry_run)
    result["requested_by"] = actor.actor_id
    return result
