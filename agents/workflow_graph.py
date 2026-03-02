from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

from agents.decision_engine import DecisionEngine, get_decision_engine
from agents.target_profiler import TargetProfiler, get_target_profiler
from backend.audit.models import create_audit_context
from backend.audit.service import AuditService, get_audit_service
from backend.workflow.state_store import WorkflowStateStore, get_workflow_state_store
from connectors.defectdojo_connector import DefectDojoConnector, get_defectdojo_connector
from connectors.scan_orchestrator import ScanOrchestrator, get_scan_orchestrator
from reports.diff_generator import DiffReportGenerator, get_diff_report_generator
from backend.security.scope_guard import ScopeGuard, get_scope_guard
from reports.generator import ReportGenerator, get_report_generator


class PocWorkflowState(TypedDict, total=False):
    workflow_name: str
    target: str
    requested_by: str
    trace_id: str
    task_id: str
    agent_id: str
    status: str
    current_step: str
    failure_reason: str
    analysis: dict[str, Any]
    target_profile: dict[str, Any]
    scan: dict[str, Any]
    llm_decision: dict[str, Any]
    verification: dict[str, Any]
    report: dict[str, Any]
    report_artifacts: dict[str, Any]
    defectdojo_sync: dict[str, Any]
    retest_context: dict[str, Any]
    source_task_id: str
    retest_task_id: str
    diff_report: dict[str, Any]
    diff_artifacts: dict[str, Any]
    state_version: int
    steps: list[str]
    audit_events: list[dict[str, str]]


def run_poc_workflow(
    *,
    target: str,
    requested_by: str = "system",
    trace_id: str | None = None,
    task_id: str | None = None,
    agent_id: str = "workflow-p1",
    scope_guard: ScopeGuard | None = None,
    audit_service: AuditService | None = None,
    scan_orchestrator: ScanOrchestrator | None = None,
    target_profiler: TargetProfiler | None = None,
    decision_engine: DecisionEngine | None = None,
    report_generator: ReportGenerator | None = None,
    defectdojo_connector: DefectDojoConnector | None = None,
    retest_context: dict[str, Any] | None = None,
    state_store: WorkflowStateStore | None = None,
) -> PocWorkflowState:
    active_scope_guard = scope_guard or get_scope_guard()
    active_audit_service = audit_service or get_audit_service()
    active_scan_orchestrator = scan_orchestrator or get_scan_orchestrator()
    active_target_profiler = target_profiler or get_target_profiler()
    active_decision_engine = decision_engine or get_decision_engine()
    active_report_generator = report_generator or get_report_generator()
    active_defectdojo_connector = defectdojo_connector or get_defectdojo_connector()
    active_state_store = state_store or get_workflow_state_store()
    graph = _build_graph(
        active_scope_guard,
        active_audit_service,
        active_scan_orchestrator,
        active_target_profiler,
        active_decision_engine,
        active_report_generator,
        active_defectdojo_connector,
        active_state_store,
    )

    context = create_audit_context(
        operator=requested_by,
        trace_id=trace_id,
        task_id=task_id,
        agent_id=agent_id,
    )
    initial_state: PocWorkflowState = {
        "workflow_name": "poc_single_target",
        "target": target,
        "requested_by": requested_by,
        "trace_id": context.trace_id,
        "task_id": context.task_id,
        "agent_id": context.agent_id,
        "status": "in_progress",
        "current_step": "init",
        "state_version": 0,
        "steps": ["init"],
        "audit_events": [],
    }
    if retest_context:
        initial_state["retest_context"] = dict(retest_context)
    initial_state["state_version"] = _persist_snapshot(
        state_store=active_state_store,
        state=initial_state,
        step="init",
        status="in_progress",
        node_input={"target": target, "requested_by": requested_by},
        node_output={"state_initialized": True},
        reason="workflow_initialized",
    )
    final_state = graph.invoke(initial_state)
    if not isinstance(final_state, dict):
        raise RuntimeError("invalid_workflow_state")
    return final_state


def replay_poc_workflow_from_task(
    *,
    task_id: str,
    scope_guard: ScopeGuard | None = None,
    audit_service: AuditService | None = None,
    scan_orchestrator: ScanOrchestrator | None = None,
    target_profiler: TargetProfiler | None = None,
    decision_engine: DecisionEngine | None = None,
    report_generator: ReportGenerator | None = None,
    defectdojo_connector: DefectDojoConnector | None = None,
    state_store: WorkflowStateStore | None = None,
) -> PocWorkflowState:
    active_state_store = state_store or get_workflow_state_store()
    snapshots = active_state_store.list_snapshots(task_id)
    if not snapshots:
        raise ValueError(f"task_not_found:{task_id}")
    init_snapshot = snapshots[0]
    init_state = dict(init_snapshot.get("state", {}))
    target = str(init_state.get("target", "")).strip()
    if not target:
        raise ValueError("invalid_initial_state_target")
    return run_poc_workflow(
        target=target,
        requested_by=str(init_state.get("requested_by", "system")),
        trace_id=str(init_state.get("trace_id", "")) or None,
        task_id=task_id,
        agent_id=str(init_state.get("agent_id", "workflow-p1")),
        scope_guard=scope_guard,
        audit_service=audit_service,
        scan_orchestrator=scan_orchestrator,
        target_profiler=target_profiler,
        decision_engine=decision_engine,
        report_generator=report_generator,
        defectdojo_connector=defectdojo_connector,
        state_store=active_state_store,
    )


def run_retest_workflow_from_task(
    *,
    task_id: str,
    scope_guard: ScopeGuard | None = None,
    audit_service: AuditService | None = None,
    scan_orchestrator: ScanOrchestrator | None = None,
    target_profiler: TargetProfiler | None = None,
    decision_engine: DecisionEngine | None = None,
    report_generator: ReportGenerator | None = None,
    defectdojo_connector: DefectDojoConnector | None = None,
    diff_report_generator: DiffReportGenerator | None = None,
    state_store: WorkflowStateStore | None = None,
) -> PocWorkflowState:
    active_scope_guard = scope_guard or get_scope_guard()
    active_audit_service = audit_service or get_audit_service()
    active_scan_orchestrator = scan_orchestrator or get_scan_orchestrator()
    active_target_profiler = target_profiler or get_target_profiler()
    active_decision_engine = decision_engine or get_decision_engine()
    active_report_generator = report_generator or get_report_generator()
    active_defectdojo_connector = defectdojo_connector or get_defectdojo_connector()
    active_diff_report_generator = diff_report_generator or get_diff_report_generator()
    active_state_store = state_store or get_workflow_state_store()

    baseline_snapshot = active_state_store.get_latest_snapshot(task_id)
    if baseline_snapshot is None:
        raise ValueError(f"task_not_found:{task_id}")
    baseline_state = dict(baseline_snapshot.get("state", {}))
    baseline_report = dict(baseline_state.get("report", {}))
    if not baseline_report:
        raise ValueError("baseline_report_missing")

    target = str(baseline_state.get("target", "")).strip()
    if not target:
        raise ValueError("invalid_baseline_target")

    source_trace_id = str(baseline_state.get("trace_id", "")).strip()
    retest_task_id = _build_retest_task_id(task_id)
    retest_trace_id = f"{source_trace_id}-retest" if source_trace_id else None
    focus_findings = _derive_focus_findings(baseline_state)
    focus_tools = _derive_focus_tools(focus_findings)
    retest_context = {
        "mode": "retest",
        "source_task_id": task_id,
        "focus_findings": focus_findings,
        "focus_tools": focus_tools,
    }

    result = run_poc_workflow(
        target=target,
        requested_by=str(baseline_state.get("requested_by", "system")),
        trace_id=retest_trace_id,
        task_id=retest_task_id,
        agent_id=f"{baseline_state.get('agent_id', 'workflow-p1')}-retest",
        scope_guard=active_scope_guard,
        audit_service=active_audit_service,
        scan_orchestrator=active_scan_orchestrator,
        target_profiler=active_target_profiler,
        decision_engine=active_decision_engine,
        report_generator=active_report_generator,
        defectdojo_connector=active_defectdojo_connector,
        retest_context=retest_context,
        state_store=active_state_store,
    )
    after_report = dict(result.get("report", {}))
    diff_report, diff_artifacts = active_diff_report_generator.generate(
        source_task_id=task_id,
        retest_task_id=retest_task_id,
        before_report=baseline_report,
        after_report=after_report,
        focus_findings=focus_findings,
        focus_tools=focus_tools,
    )
    diff_event = _record_node_event(
        audit_service=active_audit_service,
        state=result,
        action="workflow_build_diff_report",
        tool="diff_report_generator",
        decision="completed",
        reason=diff_report.get("status", "diff_generated"),
        input_payload={
            "source_task_id": task_id,
            "retest_task_id": retest_task_id,
            "before_report_id": baseline_report.get("report_id"),
            "after_report_id": after_report.get("report_id"),
        },
        output_payload={
            "diff_report_id": diff_report.get("diff_report_id"),
            "summary": diff_report.get("summary", {}),
            "artifacts": diff_artifacts,
        },
        metadata={"node": "retest_diff"},
    )
    result["diff_report"] = diff_report
    result["diff_artifacts"] = diff_artifacts
    result["retest_context"] = retest_context
    result["source_task_id"] = task_id
    result["retest_task_id"] = retest_task_id
    result["audit_events"] = _append_audit(result.get("audit_events"), diff_event)
    result["state_version"] = _persist_snapshot(
        state_store=active_state_store,
        state=result,
        step="retest_diff",
        status=str(result.get("status", "completed")),
        node_input={"source_task_id": task_id, "focus_tools": focus_tools},
        node_output={"diff_report": diff_report, "diff_artifacts": diff_artifacts},
        reason="retest_diff_generated",
    )
    return result


def resume_poc_workflow_from_task(
    *,
    task_id: str,
    scope_guard: ScopeGuard | None = None,
    audit_service: AuditService | None = None,
    scan_orchestrator: ScanOrchestrator | None = None,
    target_profiler: TargetProfiler | None = None,
    decision_engine: DecisionEngine | None = None,
    report_generator: ReportGenerator | None = None,
    defectdojo_connector: DefectDojoConnector | None = None,
    state_store: WorkflowStateStore | None = None,
) -> PocWorkflowState:
    active_scope_guard = scope_guard or get_scope_guard()
    active_audit_service = audit_service or get_audit_service()
    active_scan_orchestrator = scan_orchestrator or get_scan_orchestrator()
    active_target_profiler = target_profiler or get_target_profiler()
    active_decision_engine = decision_engine or get_decision_engine()
    active_report_generator = report_generator or get_report_generator()
    active_defectdojo_connector = defectdojo_connector or get_defectdojo_connector()
    active_state_store = state_store or get_workflow_state_store()

    snapshots = active_state_store.list_snapshots(task_id)
    if not snapshots:
        raise ValueError(f"task_not_found:{task_id}")
    snapshot = _select_resume_snapshot(snapshots)
    if snapshot is None:
        raise ValueError(f"task_not_found:{task_id}")
    state = dict(snapshot.get("state", {}))
    if not state:
        raise ValueError("invalid_task_state")
    current_step = str(snapshot.get("step", state.get("current_step", "analyze_target")))
    current_status = str(snapshot.get("status", state.get("status", "")))
    if current_status == "completed":
        return state

    nodes = _create_nodes(
        active_scope_guard,
        active_audit_service,
        active_scan_orchestrator,
        active_target_profiler,
        active_decision_engine,
        active_report_generator,
        active_defectdojo_connector,
        active_state_store,
    )
    return _resume_execution(state=state, current_step=current_step, nodes=nodes)


def _build_graph(
    scope_guard: ScopeGuard,
    audit_service: AuditService,
    scan_orchestrator: ScanOrchestrator,
    target_profiler: TargetProfiler,
    decision_engine: DecisionEngine,
    report_generator: ReportGenerator,
    defectdojo_connector: DefectDojoConnector,
    state_store: WorkflowStateStore,
):
    nodes = _create_nodes(
        scope_guard,
        audit_service,
        scan_orchestrator,
        target_profiler,
        decision_engine,
        report_generator,
        defectdojo_connector,
        state_store,
    )
    builder: StateGraph = StateGraph(PocWorkflowState)
    builder.add_node("analyze_target", nodes["analyze_target"])
    builder.add_node("scan_target", nodes["scan_target"])
    builder.add_node("llm_decide", nodes["llm_decide"])
    builder.add_node("verify_findings", nodes["verify_findings"])
    builder.add_node("build_report", nodes["build_report"])

    builder.set_entry_point("analyze_target")
    builder.add_conditional_edges(
        "analyze_target",
        _route_after_analyze,
        {
            "scan_target": "scan_target",
            "build_report": "build_report",
        },
    )
    builder.add_conditional_edges(
        "scan_target",
        _route_after_scan,
        {
            "llm_decide": "llm_decide",
            "build_report": "build_report",
        },
    )
    builder.add_edge("llm_decide", "verify_findings")
    builder.add_edge("verify_findings", "build_report")
    builder.add_edge("build_report", END)
    return builder.compile()


def _create_nodes(
    scope_guard: ScopeGuard,
    audit_service: AuditService,
    scan_orchestrator: ScanOrchestrator,
    target_profiler: TargetProfiler,
    decision_engine: DecisionEngine,
    report_generator: ReportGenerator,
    defectdojo_connector: DefectDojoConnector,
    state_store: WorkflowStateStore,
) -> dict[str, Any]:
    return {
        "analyze_target": _make_analyze_node(scope_guard, audit_service, target_profiler, state_store),
        "scan_target": _make_scan_node(audit_service, scan_orchestrator, target_profiler, state_store),
        "llm_decide": _make_llm_decide_node(audit_service, decision_engine, state_store),
        "verify_findings": _make_verify_node(audit_service, state_store),
        "build_report": _make_report_node(audit_service, report_generator, defectdojo_connector, state_store),
    }


def _route_after_analyze(state: PocWorkflowState) -> str:
    if state.get("status") == "failed":
        return "build_report"
    return "scan_target"


def _route_after_scan(state: PocWorkflowState) -> str:
    if state.get("status") == "failed":
        return "build_report"
    return "llm_decide"


def _make_analyze_node(
    scope_guard: ScopeGuard,
    audit_service: AuditService,
    target_profiler: TargetProfiler,
    state_store: WorkflowStateStore,
):
    def analyze_target(state: PocWorkflowState) -> dict[str, Any]:
        target = str(state.get("target", "")).strip()
        decision = scope_guard.authorize(target)
        profile = target_profiler.profile(target=target)
        analysis = {
            "allowed": decision.allowed,
            "reason": decision.reason,
            "matched_rule": decision.matched_rule,
            "normalized_target": decision.normalized_target,
            "target_profile": profile,
        }

        decision_label = "allowed" if decision.allowed else "blocked"
        status = "in_progress" if decision.allowed else "failed"
        step_name = "analyze_target"
        audit_event = _record_node_event(
            audit_service=audit_service,
            state=state,
            action="workflow_analyze_target",
            tool="scope_guard",
            decision=decision_label,
            reason=decision.reason,
            input_payload={"target": target},
            output_payload=analysis,
            metadata={"node": step_name},
        )

        update: dict[str, Any] = {
            "current_step": step_name,
            "status": status,
            "analysis": analysis,
            "target_profile": profile,
            "steps": _append(state.get("steps"), step_name),
            "audit_events": _append_audit(state.get("audit_events"), audit_event),
        }
        if not decision.allowed:
            update["failure_reason"] = f"scope_denied:{decision.reason}"
        merged_state = _merge_state(state, update)
        update["state_version"] = _persist_snapshot(
            state_store=state_store,
            state=merged_state,
            step=step_name,
            status=status,
            node_input={"target": target},
            node_output=analysis,
            reason=decision.reason,
        )
        return update

    return analyze_target


def _make_scan_node(
    audit_service: AuditService,
    scan_orchestrator: ScanOrchestrator,
    target_profiler: TargetProfiler,
    state_store: WorkflowStateStore,
):
    def scan_target(state: PocWorkflowState) -> dict[str, Any]:
        target = str(state.get("target", "")).strip()
        requested_by = str(state.get("requested_by", "system"))
        prior_profile = dict(state.get("target_profile", {}))
        retest_context = state.get("retest_context", {})
        force_tools: list[str] = []
        if isinstance(retest_context, dict):
            tools = retest_context.get("focus_tools", [])
            if isinstance(tools, list):
                force_tools = [str(item).strip() for item in tools if str(item).strip()]
        scan_result = scan_orchestrator.execute(
            target=target,
            requested_by=requested_by,
            strategy_hint=str(prior_profile.get("strategy_hint", "")),
            target_profile=prior_profile,
            force_tools=force_tools or None,
        )
        step_name = "scan_target"
        node_status = "in_progress"
        failure_reason = ""
        if scan_result.get("status") == "failed":
            node_status = "failed"
            failure_reason = f"scan_execution_failed:{scan_result.get('failure_reason', 'unknown')}"

        target_profile = target_profiler.profile(target=target, scan=scan_result)
        analysis = dict(state.get("analysis", {}))
        analysis["target_profile"] = target_profile

        audit_event = _record_node_event(
            audit_service=audit_service,
            state=state,
            action="workflow_scan_target",
            tool="scan_orchestrator",
            decision="allowed" if node_status != "failed" else "failed",
            reason="scan_completed" if node_status != "failed" else "scan_failed",
            input_payload={"target": target},
            output_payload={"scan": scan_result, "target_profile": target_profile},
            metadata={"node": step_name, "os_guess": target_profile.get("os_guess", "unknown")},
            raw_output=f"executed_tools={scan_result.get('executed_tools', 0)} findings={scan_result.get('finding_count', 0)}",
        )
        update = {
            "current_step": step_name,
            "analysis": analysis,
            "target_profile": target_profile,
            "scan": scan_result,
            "status": node_status,
            "steps": _append(state.get("steps"), step_name),
            "audit_events": _append_audit(state.get("audit_events"), audit_event),
        }
        if failure_reason:
            update["failure_reason"] = failure_reason
        merged_state = _merge_state(state, update)
        update["state_version"] = _persist_snapshot(
            state_store=state_store,
            state=merged_state,
            step=step_name,
            status=node_status,
            node_input={"target": target},
            node_output={"scan": scan_result, "target_profile": target_profile},
            reason=scan_result.get("failure_reason", ""),
        )
        return update

    return scan_target


def _make_llm_decide_node(
    audit_service: AuditService,
    decision_engine: DecisionEngine,
    state_store: WorkflowStateStore,
):
    def llm_decide(state: PocWorkflowState) -> dict[str, Any]:
        target = str(state.get("target", "")).strip()
        analysis = dict(state.get("analysis", {}))
        target_profile = dict(state.get("target_profile", {}))
        if target_profile and "target_profile" not in analysis:
            analysis["target_profile"] = target_profile
        scan = dict(state.get("scan", {}))
        llm_decision = decision_engine.decide(
            target=target,
            analysis=analysis,
            scan=scan,
        )
        step_name = "llm_decide"
        mode = str(llm_decision.get("mode", "unknown"))
        reason = str(llm_decision.get("summary", {}).get("overall_decision", "decision_ready"))
        audit_event = _record_node_event(
            audit_service=audit_service,
            state=state,
            action="workflow_llm_decide",
            tool="decision_engine",
            decision="allowed",
            reason=reason,
            input_payload={"target": target, "analysis": analysis, "finding_count": scan.get("finding_count", 0)},
            output_payload=llm_decision,
            metadata={"node": step_name, "mode": mode},
        )
        update = {
            "current_step": step_name,
            "llm_decision": llm_decision,
            "steps": _append(state.get("steps"), step_name),
            "audit_events": _append_audit(state.get("audit_events"), audit_event),
        }
        merged_state = _merge_state(state, update)
        update["state_version"] = _persist_snapshot(
            state_store=state_store,
            state=merged_state,
            step=step_name,
            status=str(state.get("status", "in_progress")),
            node_input={"target": target, "finding_count": scan.get("finding_count", 0)},
            node_output=llm_decision,
            reason=reason,
        )
        return update

    return llm_decide


def _make_verify_node(audit_service: AuditService, state_store: WorkflowStateStore):
    def verify_findings(state: PocWorkflowState) -> dict[str, Any]:
        scan = state.get("scan", {})
        findings = list(scan.get("findings", []))
        verified = [item for item in findings if float(item.get("confidence", 0.0)) >= 0.7]
        llm_decision = dict(state.get("llm_decision", {}))
        llm_evidence = dict(llm_decision.get("evidence_interpretation", {}))
        verification = {
            "total_findings": len(findings),
            "verified_findings": len(verified),
            "verified_items": verified,
            "decision": str(llm_evidence.get("overall_decision", "risk_confirmed" if verified else "no_confirmed_risk")),
            "llm_confidence": float(llm_evidence.get("confidence", 0.0)) if llm_evidence else 0.0,
            "llm_mode": llm_decision.get("mode", "none"),
        }
        step_name = "verify_findings"
        audit_event = _record_node_event(
            audit_service=audit_service,
            state=state,
            action="workflow_verify_findings",
            tool="verification_engine",
            decision="allowed",
            reason=verification["decision"],
            input_payload={"findings_count": len(findings), "llm_mode": llm_decision.get("mode", "none")},
            output_payload=verification,
            metadata={"node": step_name},
        )
        update = {
            "current_step": step_name,
            "verification": verification,
            "steps": _append(state.get("steps"), step_name),
            "audit_events": _append_audit(state.get("audit_events"), audit_event),
        }
        merged_state = _merge_state(state, update)
        update["state_version"] = _persist_snapshot(
            state_store=state_store,
            state=merged_state,
            step=step_name,
            status=str(state.get("status", "in_progress")),
            node_input={"findings_count": len(findings)},
            node_output=verification,
            reason=verification["decision"],
        )
        return update

    return verify_findings


def _make_report_node(
    audit_service: AuditService,
    report_generator: ReportGenerator,
    defectdojo_connector: DefectDojoConnector,
    state_store: WorkflowStateStore,
):
    def build_report(state: PocWorkflowState) -> dict[str, Any]:
        status = state.get("status", "in_progress")
        step_name = "build_report"
        final_status = "failed" if status == "failed" else "completed"
        reason = "workflow_failed" if final_status == "failed" else "workflow_completed"

        state_for_report = dict(state)
        state_for_report["status"] = final_status
        report, report_artifacts = report_generator.generate(state=state_for_report)
        defectdojo_sync = defectdojo_connector.upload_report(
            report=report,
            report_artifacts=report_artifacts,
            task_id=str(state.get("task_id", "")),
            trace_id=str(state.get("trace_id", "")),
            scan_name=f"{state.get('workflow_name', 'poc_single_target')}:{state.get('target', 'unknown')}",
        )

        audit_event = _record_node_event(
            audit_service=audit_service,
            state=state,
            action="workflow_build_report",
            tool="report_generator",
            decision=final_status,
            reason=reason,
            input_payload={"status_before_report": state.get("status"), "target": state.get("target")},
            output_payload=report,
            metadata={"node": step_name},
        )
        sync_event = _record_node_event(
            audit_service=audit_service,
            state=state,
            action="workflow_sync_defectdojo",
            tool="defectdojo_connector",
            decision=str(defectdojo_sync.get("status", "unknown")),
            reason=str(defectdojo_sync.get("reason", defectdojo_sync.get("status", "sync_done"))),
            input_payload={
                "target": state.get("target"),
                "task_id": state.get("task_id"),
                "report_id": report.get("report_id"),
            },
            output_payload=defectdojo_sync,
            metadata={"node": step_name},
        )
        update = {
            "current_step": step_name,
            "status": final_status,
            "report": report,
            "report_artifacts": report_artifacts,
            "defectdojo_sync": defectdojo_sync,
            "steps": _append(state.get("steps"), step_name),
            "audit_events": _append_audit(
                _append_audit(state.get("audit_events"), audit_event),
                sync_event,
            ),
        }
        merged_state = _merge_state(state, update)
        update["state_version"] = _persist_snapshot(
            state_store=state_store,
            state=merged_state,
            step=step_name,
            status=final_status,
            node_input={"status_before_report": state.get("status"), "target": state.get("target")},
            node_output={
                "report_id": report.get("report_id"),
                "status": report.get("status"),
                "artifacts": report_artifacts,
                "defectdojo_sync": defectdojo_sync,
            },
            reason=reason,
        )
        return update

    return build_report


def _record_node_event(
    *,
    audit_service: AuditService,
    state: PocWorkflowState,
    action: str,
    tool: str,
    decision: str,
    reason: str,
    input_payload: dict[str, Any],
    output_payload: dict[str, Any],
    metadata: dict[str, Any],
    raw_output: str | None = None,
) -> dict[str, str]:
    context = create_audit_context(
        operator=str(state.get("requested_by", "system")),
        trace_id=str(state.get("trace_id", "")) or None,
        task_id=str(state.get("task_id", "")) or None,
        agent_id=str(state.get("agent_id", "workflow-p1")),
    )
    event = audit_service.record_event(
        context=context,
        action=action,
        target=str(state.get("target", "")),
        tool=tool,
        decision=decision,
        reason=reason,
        input_payload=input_payload,
        output_payload=output_payload,
        metadata=metadata,
        raw_output=raw_output,
    )
    return {
        "event_id": event.event_id,
        "evidence_dir": event.evidence_dir,
        "tool": tool,
        "action": action,
    }


def _append(values: list[str] | None, value: str) -> list[str]:
    base = list(values or [])
    base.append(value)
    return base


def _append_audit(
    values: list[dict[str, str]] | None,
    value: dict[str, str],
) -> list[dict[str, str]]:
    base = list(values or [])
    base.append(value)
    return base


def _merge_state(state: PocWorkflowState, update: dict[str, Any]) -> PocWorkflowState:
    merged: PocWorkflowState = dict(state)
    for key, value in update.items():
        merged[key] = value
    return merged


def _persist_snapshot(
    *,
    state_store: WorkflowStateStore,
    state: PocWorkflowState,
    step: str,
    status: str,
    node_input: dict[str, Any],
    node_output: dict[str, Any],
    reason: str = "",
) -> int:
    task_id = str(state.get("task_id", "")).strip()
    trace_id = str(state.get("trace_id", "")).strip()
    if not task_id or not trace_id:
        return int(state.get("state_version", 0) or 0)
    snapshot = state_store.save_snapshot(
        task_id=task_id,
        trace_id=trace_id,
        step=step,
        status=status,
        state=dict(state),
        node_input=node_input,
        node_output=node_output,
        reason=reason,
    )
    version = int(snapshot.get("version", 0))
    state["state_version"] = version
    return version


def _select_resume_snapshot(snapshots: list[dict[str, Any]]) -> dict[str, Any]:
    latest = snapshots[-1]
    latest_status = str(latest.get("status", ""))
    latest_step = str(latest.get("step", ""))
    if latest_status == "completed" or latest_step != "build_report":
        return latest
    for candidate in reversed(snapshots[:-1]):
        step = str(candidate.get("step", ""))
        if step != "build_report":
            return candidate
    return latest


def _resume_execution(
    *,
    state: PocWorkflowState,
    current_step: str,
    nodes: dict[str, Any],
) -> PocWorkflowState:
    working_state: PocWorkflowState = dict(state)
    if str(working_state.get("status", "")) == "failed":
        working_state["status"] = "in_progress"
        working_state.pop("failure_reason", None)
    resume_step = current_step if current_step in nodes else "analyze_target"

    if resume_step == "analyze_target":
        update = nodes["analyze_target"](working_state)
        working_state = _merge_state(working_state, update)
        if working_state.get("status") == "failed":
            update = nodes["build_report"](working_state)
            return _merge_state(working_state, update)
        resume_step = "scan_target"

    if resume_step == "scan_target":
        update = nodes["scan_target"](working_state)
        working_state = _merge_state(working_state, update)
        if working_state.get("status") == "failed":
            update = nodes["build_report"](working_state)
            return _merge_state(working_state, update)
        resume_step = "llm_decide"

    if resume_step == "llm_decide":
        update = nodes["llm_decide"](working_state)
        working_state = _merge_state(working_state, update)
        resume_step = "verify_findings"

    if resume_step == "verify_findings":
        update = nodes["verify_findings"](working_state)
        working_state = _merge_state(working_state, update)
        resume_step = "build_report"

    if resume_step == "build_report":
        update = nodes["build_report"](working_state)
        working_state = _merge_state(working_state, update)

    return working_state


def _derive_focus_findings(state: dict[str, Any]) -> list[dict[str, Any]]:
    verification = state.get("verification", {})
    if isinstance(verification, dict):
        verified = verification.get("verified_items", [])
        if isinstance(verified, list) and verified:
            return [item for item in verified if isinstance(item, dict)]

    scan = state.get("scan", {})
    if isinstance(scan, dict):
        findings = scan.get("findings", [])
        if isinstance(findings, list):
            filtered = []
            for item in findings:
                if not isinstance(item, dict):
                    continue
                confidence = float(item.get("confidence", 0.0))
                if confidence >= 0.7:
                    filtered.append(item)
            if filtered:
                return filtered
            return [item for item in findings if isinstance(item, dict)][:10]
    return []


def _derive_focus_tools(findings: list[dict[str, Any]]) -> list[str]:
    tools = []
    for item in findings:
        tool = str(item.get("tool", "")).strip()
        if tool:
            tools.append(tool)
    return sorted(set(tools))


def _build_retest_task_id(source_task_id: str) -> str:
    suffix = datetime.now(UTC).strftime("%Y%m%d%H%M%S%f")
    return f"{source_task_id}-retest-{suffix}"
