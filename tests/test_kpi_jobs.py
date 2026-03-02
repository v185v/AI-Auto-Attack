from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path

from backend.observability.kpi_jobs import KPIJobService, KPIJobSettings
from backend.workflow.state_store import StateStoreSettings, WorkflowStateStore


class StubMetricsService:
    def summarize(self, *, window_hours=None) -> dict:
        return {
            "window_hours": window_hours or 168,
            "total_tasks": 3,
            "completed_tasks": 3,
            "failed_tasks": 0,
            "failure_rate": 0.0,
        }

    def summarize_cost(self, *, window_hours=None) -> dict:
        return {
            "window_hours": window_hours or 168,
            "total_tasks": 3,
            "avg_estimated_cost_per_task_usd": 0.023,
            "avg_llm_latency_ms": 210.0,
            "cache_hit_rate": 0.4,
        }


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="seconds")


def _save(
    store: WorkflowStateStore,
    *,
    task_id: str,
    trace_id: str,
    step: str,
    status: str,
    timestamp: str,
    state: dict,
) -> None:
    store.save_snapshot(
        task_id=task_id,
        trace_id=trace_id,
        step=step,
        status=status,
        reason="test",
        timestamp=timestamp,
        state=state,
        node_input={},
        node_output={},
    )


def test_kpi_job_summary_and_export(tmp_path) -> None:
    state_store = WorkflowStateStore(StateStoreSettings(directory=str(tmp_path / "state")))
    now = datetime.now(UTC)

    # source task
    _save(
        state_store,
        task_id="task-source-1",
        trace_id="trace-source-1",
        step="init",
        status="in_progress",
        timestamp=_iso(now - timedelta(hours=3)),
        state={"task_id": "task-source-1", "trace_id": "trace-source-1", "status": "in_progress"},
    )
    _save(
        state_store,
        task_id="task-source-1",
        trace_id="trace-source-1",
        step="build_report",
        status="completed",
        timestamp=_iso(now - timedelta(hours=2)),
        state={
            "task_id": "task-source-1",
            "trace_id": "trace-source-1",
            "status": "completed",
            "scan": {"finding_count": 2},
            "verification": {"verified_findings": 1},
        },
    )

    # retest task
    _save(
        state_store,
        task_id="task-source-1-retest",
        trace_id="trace-source-1-retest",
        step="build_report",
        status="completed",
        timestamp=_iso(now - timedelta(hours=1)),
        state={
            "task_id": "task-source-1-retest",
            "trace_id": "trace-source-1-retest",
            "status": "completed",
            "source_task_id": "task-source-1",
            "scan": {"finding_count": 1},
            "verification": {"verified_findings": 1},
            "diff_report": {"summary": {"persistent_count": 1, "resolved_count": 1}},
        },
    )

    # no-finding task
    _save(
        state_store,
        task_id="task-clean",
        trace_id="trace-clean",
        step="build_report",
        status="completed",
        timestamp=_iso(now - timedelta(minutes=30)),
        state={
            "task_id": "task-clean",
            "trace_id": "trace-clean",
            "status": "completed",
            "scan": {"finding_count": 0},
            "verification": {"verified_findings": 0},
        },
    )

    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(parents=True, exist_ok=True)
    req_dir = evidence_root / "2026-03-02" / "trace-approval" / "evt-req"
    dec_dir = evidence_root / "2026-03-02" / "trace-approval" / "evt-dec"
    req_dir.mkdir(parents=True, exist_ok=True)
    dec_dir.mkdir(parents=True, exist_ok=True)
    (req_dir / "output.json").write_text(json.dumps({"approval_id": "ap-1"}) + "\n", encoding="utf-8")
    (dec_dir / "output.json").write_text(json.dumps({"approval_id": "ap-1"}) + "\n", encoding="utf-8")
    index_path = evidence_root / "audit-events.jsonl"
    index_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "timestamp": _iso(now - timedelta(minutes=5)),
                        "action": "validate_action",
                        "reason": "approval_required",
                        "evidence_dir": req_dir.as_posix(),
                    }
                ),
                json.dumps(
                    {
                        "timestamp": _iso(now - timedelta(minutes=4, seconds=50)),
                        "action": "validate_action",
                        "reason": "approval_pending",
                        "evidence_dir": req_dir.as_posix(),
                    }
                ),
                json.dumps(
                    {
                        "timestamp": _iso(now - timedelta(minutes=4, seconds=20)),
                        "action": "approval_decision",
                        "reason": "approval_state_updated",
                        "evidence_dir": dec_dir.as_posix(),
                    }
                ),
                json.dumps(
                    {
                        "timestamp": _iso(now - timedelta(minutes=4, seconds=10)),
                        "action": "approval_decision",
                        "reason": "approval_state_updated",
                        "evidence_dir": dec_dir.as_posix(),
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    service = KPIJobService(
        state_store=state_store,
        metrics_service=StubMetricsService(),
        settings=KPIJobSettings(
            output_dir=(tmp_path / "kpi").as_posix(),
            evidence_root=evidence_root.as_posix(),
            weekly_window_hours=168,
            monthly_window_hours=720,
        ),
    )

    summary = service.generate_summary(period="weekly")
    assert summary["period"] == "weekly"
    assert summary["kpis"]["coverage_rate"] == 0.6667
    assert summary["kpis"]["false_positive_rate"] == 0.3333
    assert summary["kpis"]["reproducibility_rate"] == 1.0
    assert summary["kpis"]["closure_cycle_seconds_avg"] is not None
    assert summary["kpis"]["single_task_cost_usd_avg"] == 0.023
    assert summary["kpis"]["approval_lead_time_seconds_avg"] == 40.0
    assert summary["details"]["approval_metrics"]["approval_requests"] == 1
    assert summary["details"]["approval_metrics"]["approval_decisions"] == 1

    exported = service.export_summary(period="weekly")
    artifacts = exported["artifacts"]
    assert Path(artifacts["json_path"]).exists()
    assert Path(artifacts["markdown_path"]).exists()
