from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from agents.decision_engine import DecisionEngine, get_decision_engine
from agents.workflow_graph import run_poc_workflow
from backend.analysis.path_graph import build_attack_path_graph
from backend.audit.service import AuditService, get_audit_service
from backend.scheduler.resource_quota import ResourceQuotaManager, get_resource_quota_manager
from backend.security.scope_guard import ScopeGuard, get_scope_guard
from connectors.defectdojo_connector import DefectDojoConnector, get_defectdojo_connector
from reports.path_view_generator import PathViewGenerator, get_path_view_generator
from connectors.scan_orchestrator import ScanOrchestrator, get_scan_orchestrator
from reports.generator import ReportGenerator, get_report_generator


@dataclass(frozen=True)
class StageNode:
    node_id: str
    target: str
    depends_on: tuple[str, ...]
    requested_by: str
    priority: int


def run_multi_stage_workflow(
    *,
    nodes: list[dict[str, Any]],
    requested_by: str = "system",
    continue_on_error: bool = False,
    requested_parallelism: int = 1,
    trace_id: str | None = None,
    task_id_prefix: str | None = None,
    agent_id: str = "workflow-p6-multi-stage",
    scope_guard: ScopeGuard | None = None,
    audit_service: AuditService | None = None,
    scan_orchestrator: ScanOrchestrator | None = None,
    decision_engine: DecisionEngine | None = None,
    report_generator: ReportGenerator | None = None,
    defectdojo_connector: DefectDojoConnector | None = None,
    resource_quota: ResourceQuotaManager | None = None,
    path_view_generator: PathViewGenerator | None = None,
) -> dict[str, Any]:
    parsed = _parse_nodes(nodes=nodes, default_requested_by=requested_by)
    by_id = {item.node_id: item for item in parsed}
    _validate_dependencies(by_id)

    active_scope_guard = scope_guard or get_scope_guard()
    active_audit_service = audit_service or get_audit_service()
    active_scan_orchestrator = scan_orchestrator or get_scan_orchestrator()
    active_decision_engine = decision_engine or get_decision_engine()
    active_report_generator = report_generator or get_report_generator()
    active_defectdojo_connector = defectdojo_connector or get_defectdojo_connector()
    active_resource_quota = resource_quota or get_resource_quota_manager()
    active_path_view_generator = path_view_generator or get_path_view_generator()

    quota = active_resource_quota.check_run(
        target_count=len(parsed),
        requested_parallelism=requested_parallelism,
    )
    if not quota.allowed:
        raise ValueError(f"quota_rejected:{quota.reason}")

    base_trace_id = trace_id or f"trace-multi-{uuid4().hex[:8]}"
    base_task_prefix = task_id_prefix or f"task-multi-{uuid4().hex[:8]}"
    statuses: dict[str, str] = {}
    pending_ids = {item.node_id for item in parsed}
    execution_order: list[str] = []
    node_results: list[dict[str, Any]] = []
    terminal = {"completed", "failed", "skipped"}

    while pending_ids:
        progressed = False
        ready: list[StageNode] = []
        for node_id in sorted(pending_ids):
            node = by_id[node_id]
            dep_statuses = [statuses.get(dep) for dep in node.depends_on]
            if any(status is None for status in dep_statuses):
                continue
            if not continue_on_error and any(status in {"failed", "skipped"} for status in dep_statuses):
                statuses[node.node_id] = "skipped"
                pending_ids.remove(node.node_id)
                node_results.append(
                    {
                        "id": node.node_id,
                        "target": node.target,
                        "depends_on": list(node.depends_on),
                        "status": "skipped",
                        "failure_reason": "dependency_failed",
                        "task_id": f"{base_task_prefix}-{node.node_id}",
                        "trace_id": f"{base_trace_id}-{node.node_id}",
                    }
                )
                progressed = True
                continue
            if continue_on_error:
                if all(status in terminal for status in dep_statuses):
                    ready.append(node)
            else:
                if all(status == "completed" for status in dep_statuses):
                    ready.append(node)

        if ready:
            ready.sort(key=lambda item: (item.priority, item.node_id))
            batch = ready[: max(1, quota.applied_parallelism)]
            batch_results: dict[str, dict[str, Any]] = {}
            max_workers = max(1, min(len(batch), int(quota.applied_parallelism)))
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {
                    pool.submit(
                        _run_stage_node,
                        node=node,
                        base_task_prefix=base_task_prefix,
                        base_trace_id=base_trace_id,
                        agent_id=agent_id,
                        scope_guard=active_scope_guard,
                        audit_service=active_audit_service,
                        scan_orchestrator=active_scan_orchestrator,
                        decision_engine=active_decision_engine,
                        report_generator=active_report_generator,
                        defectdojo_connector=active_defectdojo_connector,
                    ): node
                    for node in batch
                }
                for future in as_completed(futures):
                    node = futures[future]
                    try:
                        batch_results[node.node_id] = future.result()
                    except Exception as exc:
                        batch_results[node.node_id] = _failed_stage_node(node, base_task_prefix, base_trace_id, exc)

            for node in batch:
                pending_ids.remove(node.node_id)
                execution_order.append(node.node_id)
                result = batch_results.get(node.node_id) or _failed_stage_node(
                    node=node,
                    base_task_prefix=base_task_prefix,
                    base_trace_id=base_trace_id,
                    error=RuntimeError("stage_result_missing"),
                )
                statuses[node.node_id] = str(result.get("status", "failed"))
                node_results.append(result)
                progressed = True
            continue

        if not progressed:
            for node_id in sorted(pending_ids):
                node = by_id[node_id]
                statuses[node.node_id] = "skipped"
                node_results.append(
                    {
                        "id": node.node_id,
                        "target": node.target,
                        "depends_on": list(node.depends_on),
                        "status": "skipped",
                        "failure_reason": "dependency_unresolved",
                        "task_id": f"{base_task_prefix}-{node.node_id}",
                        "trace_id": f"{base_trace_id}-{node.node_id}",
                    }
                )
            pending_ids.clear()

    completed_count = sum(1 for item in node_results if item.get("status") == "completed")
    failed_count = sum(1 for item in node_results if item.get("status") == "failed")
    skipped_count = sum(1 for item in node_results if item.get("status") == "skipped")
    if failed_count == 0 and skipped_count == 0:
        workflow_status = "completed"
    elif failed_count > 0 and not continue_on_error:
        workflow_status = "failed"
    else:
        workflow_status = "completed_with_issues"

    path_graph = build_attack_path_graph(nodes=node_results)
    path_view, path_artifacts = active_path_view_generator.generate(
        run_id=base_task_prefix,
        workflow_result={
            "workflow_name": "multi_stage",
            "status": workflow_status,
        },
        path_graph=path_graph,
    )

    return {
        "workflow_name": "multi_stage",
        "status": workflow_status,
        "continue_on_error": continue_on_error,
        "requested_parallelism": int(requested_parallelism),
        "applied_parallelism": int(quota.applied_parallelism),
        "quota": quota.to_dict(),
        "trace_id": base_trace_id,
        "task_id_prefix": base_task_prefix,
        "execution_order": execution_order,
        "summary": {
            "total_nodes": len(node_results),
            "completed_nodes": completed_count,
            "failed_nodes": failed_count,
            "skipped_nodes": skipped_count,
        },
        "nodes": node_results,
        "path_graph": path_graph,
        "path_view": path_view,
        "path_artifacts": path_artifacts,
    }


def _parse_nodes(*, nodes: list[dict[str, Any]], default_requested_by: str) -> list[StageNode]:
    if not nodes:
        raise ValueError("nodes_required")
    parsed: list[StageNode] = []
    seen = set()
    for raw in nodes:
        node_id = str(raw.get("id", "")).strip()
        target = str(raw.get("target", "")).strip()
        if not node_id:
            raise ValueError("invalid_node_id")
        if not target:
            raise ValueError(f"invalid_target:{node_id}")
        if node_id in seen:
            raise ValueError(f"duplicate_node_id:{node_id}")
        seen.add(node_id)
        depends = raw.get("depends_on", [])
        if not isinstance(depends, list):
            raise ValueError(f"invalid_depends_on:{node_id}")
        depends_tuple = tuple(str(item).strip() for item in depends if str(item).strip())
        priority = int(raw.get("priority", 100))
        node_requested_by = str(raw.get("requested_by", default_requested_by)).strip() or default_requested_by
        parsed.append(
            StageNode(
                node_id=node_id,
                target=target,
                depends_on=depends_tuple,
                requested_by=node_requested_by,
                priority=priority,
            )
        )
    return parsed


def _validate_dependencies(nodes: dict[str, StageNode]) -> None:
    for node in nodes.values():
        for dep in node.depends_on:
            if dep not in nodes:
                raise ValueError(f"dependency_not_found:{node.node_id}:{dep}")
            if dep == node.node_id:
                raise ValueError(f"dependency_self_reference:{node.node_id}")

    visited: dict[str, int] = {}
    # 0=unvisited,1=visiting,2=done
    for node_id in nodes.keys():
        if visited.get(node_id, 0) == 0:
            _dfs_validate(node_id, nodes, visited)


def _dfs_validate(node_id: str, nodes: dict[str, StageNode], visited: dict[str, int]) -> None:
    visited[node_id] = 1
    node = nodes[node_id]
    for dep in node.depends_on:
        state = visited.get(dep, 0)
        if state == 1:
            raise ValueError(f"dependency_cycle_detected:{node_id}:{dep}")
        if state == 0:
            _dfs_validate(dep, nodes, visited)
    visited[node_id] = 2


def _run_stage_node(
    *,
    node: StageNode,
    base_task_prefix: str,
    base_trace_id: str,
    agent_id: str,
    scope_guard: ScopeGuard,
    audit_service: AuditService,
    scan_orchestrator: ScanOrchestrator,
    decision_engine: DecisionEngine,
    report_generator: ReportGenerator,
    defectdojo_connector: DefectDojoConnector,
) -> dict[str, Any]:
    task_id = f"{base_task_prefix}-{node.node_id}"
    node_trace_id = f"{base_trace_id}-{node.node_id}"
    result = run_poc_workflow(
        target=node.target,
        requested_by=node.requested_by,
        trace_id=node_trace_id,
        task_id=task_id,
        agent_id=f"{agent_id}-{node.node_id}",
        scope_guard=scope_guard,
        audit_service=audit_service,
        scan_orchestrator=scan_orchestrator,
        decision_engine=decision_engine,
        report_generator=report_generator,
        defectdojo_connector=defectdojo_connector,
    )
    final_status = str(result.get("status", "failed"))
    if final_status not in {"completed", "failed"}:
        final_status = "failed"
    return {
        "id": node.node_id,
        "target": node.target,
        "depends_on": list(node.depends_on),
        "status": final_status,
        "task_id": result.get("task_id", task_id),
        "trace_id": result.get("trace_id", node_trace_id),
        "failure_reason": result.get("failure_reason", ""),
        "report_artifacts": result.get("report_artifacts", {}),
        "summary": {
            "finding_count": int(result.get("scan", {}).get("finding_count", 0)),
            "verified_findings": int(result.get("verification", {}).get("verified_findings", 0)),
        },
    }


def _failed_stage_node(node: StageNode, base_task_prefix: str, base_trace_id: str, error: Exception) -> dict[str, Any]:
    task_id = f"{base_task_prefix}-{node.node_id}"
    node_trace_id = f"{base_trace_id}-{node.node_id}"
    return {
        "id": node.node_id,
        "target": node.target,
        "depends_on": list(node.depends_on),
        "status": "failed",
        "task_id": task_id,
        "trace_id": node_trace_id,
        "failure_reason": f"workflow_exception:{type(error).__name__}",
        "report_artifacts": {},
        "summary": {
            "finding_count": 0,
            "verified_findings": 0,
        },
    }
