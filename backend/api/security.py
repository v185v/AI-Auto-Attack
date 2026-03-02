from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from backend.auth.rbac import Actor, get_actor, require_permission
from backend.audit.models import AuditContext, create_audit_context
from backend.audit.service import AuditService, get_audit_service
from backend.security.action_gate import ActionDecision, ActionGate, get_action_gate
from backend.security.approval_store import (
    ApprovalStatus,
    ApprovalStore,
    get_approval_store,
)
from backend.security.scope_guard import ScopeDecision, ScopeGuard, get_scope_guard

router = APIRouter(tags=["security"])


class ActionValidationRequest(BaseModel):
    target: str = Field(..., min_length=1)
    command: str = Field(..., min_length=1)
    requested_by: str = Field(default="system", min_length=1)
    approval_id: str | None = None
    trace_id: str | None = None
    task_id: str | None = None
    agent_id: str = Field(default="api-gateway", min_length=1)


class ApprovalDecisionRequest(BaseModel):
    status: ApprovalStatus
    approver: str = Field(..., min_length=1)
    trace_id: str | None = None
    task_id: str | None = None
    agent_id: str = Field(default="approval-gate", min_length=1)


def scope_guard_dep() -> ScopeGuard:
    return get_scope_guard()


def action_gate_dep() -> ActionGate:
    return get_action_gate()


def approval_store_dep() -> ApprovalStore:
    return get_approval_store()


def audit_service_dep() -> AuditService:
    return get_audit_service()


def actor_dep(actor: Actor = Depends(get_actor)) -> Actor:
    return actor


@router.post("/actions/validate")
def validate_action(
    payload: ActionValidationRequest,
    scope_guard: ScopeGuard = Depends(scope_guard_dep),
    action_gate: ActionGate = Depends(action_gate_dep),
    audit_service: AuditService = Depends(audit_service_dep),
    actor: Actor = Depends(actor_dep),
) -> dict:
    require_permission(actor, "actions:validate")
    context = create_audit_context(
        operator=actor.actor_id,
        trace_id=payload.trace_id,
        task_id=payload.task_id,
        agent_id=payload.agent_id,
    )

    scope_decision = scope_guard.authorize(payload.target)
    if not scope_decision.allowed:
        detail = _scope_reject_detail(scope_decision)
        audit_event = audit_service.record_event(
            context=context,
            action="validate_action",
            target=payload.target,
            tool="scope_guard",
            decision="blocked",
            reason=scope_decision.reason,
            input_payload=payload.model_dump(),
            output_payload=detail,
            metadata={"stage": "scope_guard", "command": payload.command},
        )
        detail.update(_audit_detail(audit_event.event_id, audit_event.evidence_dir, context))
        raise HTTPException(
            status_code=403,
            detail=detail,
        )

    action_decision = action_gate.evaluate(
        target=payload.target,
        command=payload.command,
        requested_by=actor.actor_id,
        approval_id=payload.approval_id,
    )
    if not action_decision.allowed:
        status_code = 409 if action_decision.reason in {"approval_required", "approval_pending"} else 403
        detail = _action_reject_detail(action_decision)
        decision_label = "pending_approval" if action_decision.reason in {"approval_required", "approval_pending"} else "blocked"
        audit_event = audit_service.record_event(
            context=context,
            action="validate_action",
            target=payload.target,
            tool="action_gate",
            decision=decision_label,
            reason=action_decision.reason,
            input_payload=payload.model_dump(),
            output_payload=detail,
            metadata={
                "stage": "action_gate",
                "command": payload.command,
                "risk_level": action_decision.risk_level,
            },
        )
        detail.update(_audit_detail(audit_event.event_id, audit_event.evidence_dir, context))
        raise HTTPException(
            status_code=status_code,
            detail=detail,
        )

    response = {
        "allowed": True,
        "scope": {
            "reason": scope_decision.reason,
            "matched_rule": scope_decision.matched_rule,
            "normalized_target": scope_decision.normalized_target,
        },
        "action": {
            "reason": action_decision.reason,
            "risk_level": action_decision.risk_level,
            "command_token": action_decision.command_token,
            "approval_id": action_decision.approval_id,
            "approval_status": action_decision.approval_status,
        },
    }
    audit_event = audit_service.record_event(
        context=context,
        action="validate_action",
        target=payload.target,
        tool=action_decision.command_token or "action_gate",
        decision="allowed",
        reason=action_decision.reason,
        input_payload=payload.model_dump(),
        output_payload=response,
        metadata={"stage": "action_gate", "command": payload.command, "risk_level": action_decision.risk_level},
    )
    response["audit"] = _audit_detail(audit_event.event_id, audit_event.evidence_dir, context)
    return response


@router.get("/approvals")
def list_approvals(
    status: ApprovalStatus | None = Query(default=None),
    approval_store: ApprovalStore = Depends(approval_store_dep),
    actor: Actor = Depends(actor_dep),
) -> dict:
    require_permission(actor, "approvals:read")
    records = approval_store.list(status=status)
    return {"items": [record.to_dict() for record in records]}


@router.get("/approvals/{approval_id}")
def get_approval(
    approval_id: str,
    approval_store: ApprovalStore = Depends(approval_store_dep),
    actor: Actor = Depends(actor_dep),
) -> dict:
    require_permission(actor, "approvals:read")
    record = approval_store.get(approval_id)
    if record is None:
        raise HTTPException(status_code=404, detail={"reason": "approval_not_found"})
    return record.to_dict()


@router.post("/approvals/{approval_id}/decision")
def decide_approval(
    approval_id: str,
    payload: ApprovalDecisionRequest,
    approval_store: ApprovalStore = Depends(approval_store_dep),
    audit_service: AuditService = Depends(audit_service_dep),
    actor: Actor = Depends(actor_dep),
) -> dict:
    require_permission(actor, "approvals:decide")
    if payload.approver != actor.actor_id:
        raise HTTPException(
            status_code=400,
            detail={"reason": "approver_actor_mismatch"},
        )
    context = create_audit_context(
        operator=actor.actor_id,
        trace_id=payload.trace_id,
        task_id=payload.task_id,
        agent_id=payload.agent_id,
    )
    record, changed = approval_store.decide_with_result(
        approval_id=approval_id,
        status=payload.status,
        approver=actor.actor_id,
    )
    if record is None:
        detail = {"reason": "approval_not_found", "approval_id": approval_id}
        audit_event = audit_service.record_event(
            context=context,
            action="approval_decision",
            target=approval_id,
            tool="approval_gate",
            decision="blocked",
            reason="approval_not_found",
            input_payload=payload.model_dump(),
            output_payload=detail,
            metadata={"stage": "approval_gate"},
        )
        detail.update(_audit_detail(audit_event.event_id, audit_event.evidence_dir, context))
        raise HTTPException(status_code=404, detail=detail)
    response = record.to_dict()
    reason = "approval_state_updated" if changed else "approval_state_unchanged"
    audit_event = audit_service.record_event(
        context=context,
        action="approval_decision",
        target=record.target,
        tool="approval_gate",
        decision=record.status,
        reason=reason,
        input_payload=payload.model_dump(),
        output_payload=response,
        metadata={
            "approval_id": approval_id,
            "risk_level": record.risk_level,
            "stage": "approval_gate",
            "changed": changed,
        },
    )
    response["audit"] = _audit_detail(audit_event.event_id, audit_event.evidence_dir, context)
    return response


def _scope_reject_detail(scope_decision: ScopeDecision) -> dict:
    return {
        "allowed": False,
        "reason": scope_decision.reason,
        "matched_rule": scope_decision.matched_rule,
        "normalized_target": scope_decision.normalized_target,
    }


def _action_reject_detail(action_decision: ActionDecision) -> dict:
    return {
        "allowed": False,
        "reason": action_decision.reason,
        "risk_level": action_decision.risk_level,
        "command_token": action_decision.command_token,
        "approval_id": action_decision.approval_id,
        "approval_status": action_decision.approval_status,
    }


def _audit_detail(event_id: str, evidence_dir: str, context: AuditContext) -> dict:
    return {
        "audit_event_id": event_id,
        "evidence_dir": evidence_dir,
        "trace_id": context.trace_id,
        "task_id": context.task_id,
        "agent_id": context.agent_id,
    }
