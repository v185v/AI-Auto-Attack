from __future__ import annotations

from datetime import UTC, datetime, timedelta

from backend.observability.metrics import (
    CostControlSettings,
    ErrorBudgetSettings,
    WorkflowMetricsService,
    classify_failure,
)
from backend.workflow.state_store import StateStoreSettings, WorkflowStateStore


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="seconds")


def _save(
    store: WorkflowStateStore,
    *,
    task_id: str,
    trace_id: str,
    step: str,
    status: str,
    reason: str,
    timestamp: str,
    state: dict,
) -> None:
    store.save_snapshot(
        task_id=task_id,
        trace_id=trace_id,
        step=step,
        status=status,
        reason=reason,
        timestamp=timestamp,
        state=state,
        node_input={},
        node_output={},
    )


def test_classify_failure_known_and_unknown_codes() -> None:
    known = classify_failure("scope_denied:target_out_of_scope", "analyze_target")
    assert known["code"] == "POLICY_SCOPE_DENIED"
    assert known["category"] == "policy"
    assert known["retriable"] is False

    unknown = classify_failure("some_new_failure_reason", "scan_target")
    assert unknown["code"] == "UNKNOWN_FAILURE"
    assert unknown["category"] == "unknown"


def test_workflow_metrics_summary_and_failures(tmp_path) -> None:
    store = WorkflowStateStore(StateStoreSettings(directory=str(tmp_path / "state")))
    now = datetime.now(UTC)

    # task-recovered: fail -> recover
    task_id = "task-recovered"
    trace_id = "trace-recovered"
    _save(
        store,
        task_id=task_id,
        trace_id=trace_id,
        step="init",
        status="in_progress",
        reason="workflow_initialized",
        timestamp=_iso(now - timedelta(minutes=15)),
        state={"task_id": task_id, "trace_id": trace_id, "status": "in_progress"},
    )
    _save(
        store,
        task_id=task_id,
        trace_id=trace_id,
        step="scan_target",
        status="failed",
        reason="all_tools_failed",
        timestamp=_iso(now - timedelta(minutes=10)),
        state={
            "task_id": task_id,
            "trace_id": trace_id,
            "status": "failed",
            "failure_reason": "scan_execution_failed:all_tools_failed",
        },
    )
    _save(
        store,
        task_id=task_id,
        trace_id=trace_id,
        step="build_report",
        status="completed",
        reason="workflow_completed",
        timestamp=_iso(now - timedelta(minutes=5)),
        state={"task_id": task_id, "trace_id": trace_id, "status": "completed"},
    )

    # task-failed: terminal failed
    task_id = "task-failed"
    trace_id = "trace-failed"
    _save(
        store,
        task_id=task_id,
        trace_id=trace_id,
        step="init",
        status="in_progress",
        reason="workflow_initialized",
        timestamp=_iso(now - timedelta(minutes=14)),
        state={"task_id": task_id, "trace_id": trace_id, "status": "in_progress"},
    )
    _save(
        store,
        task_id=task_id,
        trace_id=trace_id,
        step="analyze_target",
        status="failed",
        reason="target_out_of_scope",
        timestamp=_iso(now - timedelta(minutes=9)),
        state={
            "task_id": task_id,
            "trace_id": trace_id,
            "status": "failed",
            "failure_reason": "scope_denied:target_out_of_scope",
        },
    )
    _save(
        store,
        task_id=task_id,
        trace_id=trace_id,
        step="build_report",
        status="failed",
        reason="workflow_failed",
        timestamp=_iso(now - timedelta(minutes=4)),
        state={
            "task_id": task_id,
            "trace_id": trace_id,
            "status": "failed",
            "failure_reason": "scope_denied:target_out_of_scope",
        },
    )

    # task-success: clean completion
    task_id = "task-success"
    trace_id = "trace-success"
    _save(
        store,
        task_id=task_id,
        trace_id=trace_id,
        step="init",
        status="in_progress",
        reason="workflow_initialized",
        timestamp=_iso(now - timedelta(minutes=12)),
        state={"task_id": task_id, "trace_id": trace_id, "status": "in_progress"},
    )
    _save(
        store,
        task_id=task_id,
        trace_id=trace_id,
        step="build_report",
        status="completed",
        reason="workflow_completed",
        timestamp=_iso(now - timedelta(minutes=3)),
        state={"task_id": task_id, "trace_id": trace_id, "status": "completed"},
    )

    service = WorkflowMetricsService(
        state_store=store,
        settings=ErrorBudgetSettings(
            max_failure_rate=0.2,
            min_retry_success_rate=0.6,
            max_mttr_seconds=1800,
            default_window_hours=24,
        ),
        cost_settings=CostControlSettings(
            max_per_task_usd=1.0,
            max_llm_latency_ms=15000,
            default_window_hours=24,
        ),
    )

    summary = service.summarize(window_hours=24)
    assert summary["total_tasks"] == 3
    assert summary["completed_tasks"] == 2
    assert summary["failed_tasks"] == 1
    assert summary["tasks_with_failures"] == 2
    assert summary["recovered_tasks"] == 1
    assert summary["retry_success_rate"] == 0.5
    assert summary["mttr_seconds_avg"] == 300.0
    assert summary["error_budget"]["breached"] is True
    assert summary["top_errors"][0]["code"] == "POLICY_SCOPE_DENIED"

    failures = service.list_failures(window_hours=24, limit=10)
    assert failures["total"] == 2
    codes = {item["error"]["code"] for item in failures["items"]}
    assert "POLICY_SCOPE_DENIED" in codes
    assert "TOOL_EXECUTION_FAILED" in codes
    recovered = [item for item in failures["items"] if item["task_id"] == "task-recovered"]
    assert recovered and recovered[0]["recovered"] is True


def test_workflow_metrics_cost_summary(tmp_path) -> None:
    store = WorkflowStateStore(StateStoreSettings(directory=str(tmp_path / "state")))
    now = datetime.now(UTC)

    task_id = "task-cost-1"
    trace_id = "trace-cost-1"
    _save(
        store,
        task_id=task_id,
        trace_id=trace_id,
        step="llm_decide",
        status="in_progress",
        reason="decision_ready",
        timestamp=_iso(now - timedelta(minutes=5)),
        state={
            "task_id": task_id,
            "trace_id": trace_id,
            "status": "in_progress",
            "llm_decision": {
                "mode": "llm",
                "model": "deepseek/deepseek-chat",
                "llm_runtime": {
                    "attempted": True,
                    "cache_hit": False,
                    "latency_ms": 300,
                    "estimated_cost_usd": 0.012,
                },
            },
        },
    )
    _save(
        store,
        task_id=task_id,
        trace_id=trace_id,
        step="build_report",
        status="completed",
        reason="workflow_completed",
        timestamp=_iso(now - timedelta(minutes=4)),
        state={"task_id": task_id, "trace_id": trace_id, "status": "completed"},
    )

    task_id = "task-cost-2"
    trace_id = "trace-cost-2"
    _save(
        store,
        task_id=task_id,
        trace_id=trace_id,
        step="llm_decide",
        status="in_progress",
        reason="decision_ready",
        timestamp=_iso(now - timedelta(minutes=3)),
        state={
            "task_id": task_id,
            "trace_id": trace_id,
            "status": "in_progress",
            "llm_decision": {
                "mode": "llm",
                "model": "deepseek/deepseek-chat",
                "llm_runtime": {
                    "attempted": True,
                    "cache_hit": True,
                    "latency_ms": 0,
                    "estimated_cost_usd": 0.0,
                },
            },
        },
    )
    _save(
        store,
        task_id=task_id,
        trace_id=trace_id,
        step="build_report",
        status="completed",
        reason="workflow_completed",
        timestamp=_iso(now - timedelta(minutes=2)),
        state={"task_id": task_id, "trace_id": trace_id, "status": "completed"},
    )

    service = WorkflowMetricsService(
        state_store=store,
        settings=ErrorBudgetSettings(
            max_failure_rate=0.2,
            min_retry_success_rate=0.6,
            max_mttr_seconds=1800,
            default_window_hours=24,
        ),
        cost_settings=CostControlSettings(
            max_per_task_usd=1.0,
            max_llm_latency_ms=15000,
            default_window_hours=24,
        ),
    )

    summary = service.summarize_cost(window_hours=24)
    assert summary["total_tasks"] == 2
    assert summary["llm_calls"] == 2
    assert summary["cache_hits"] == 1
    assert summary["cache_hit_rate"] == 0.5
    assert summary["total_estimated_cost_usd"] == 0.012
    assert summary["avg_estimated_cost_per_task_usd"] == 0.006
    assert summary["avg_llm_latency_ms"] == 300.0
    assert summary["budget"]["breached"] is False
