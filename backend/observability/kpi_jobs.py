from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
import json
from pathlib import Path
from typing import Any, Literal

from backend.core.config import get_settings
from backend.observability.metrics import WorkflowMetricsService, get_workflow_metrics_service
from backend.workflow.state_store import WorkflowStateStore, get_workflow_state_store


Period = Literal["weekly", "monthly"]


@dataclass(frozen=True)
class KPIJobSettings:
    output_dir: str
    evidence_root: str
    weekly_window_hours: int
    monthly_window_hours: int


class KPIJobService:
    def __init__(
        self,
        *,
        state_store: WorkflowStateStore,
        metrics_service: WorkflowMetricsService,
        settings: KPIJobSettings,
    ) -> None:
        self.state_store = state_store
        self.metrics_service = metrics_service
        self.settings = settings

    def generate_summary(self, *, period: Period) -> dict[str, Any]:
        window_hours = self._window_hours(period)
        reliability = self.metrics_service.summarize(window_hours=window_hours)
        cost = self.metrics_service.summarize_cost(window_hours=window_hours)
        finding_metrics = self._finding_metrics(window_hours=window_hours)
        reproducibility_metrics = self._reproducibility_metrics(window_hours=window_hours)
        closure_metrics = self._closure_cycle_metrics(window_hours=window_hours)
        approval_metrics = self._approval_metrics(window_hours=window_hours)

        return {
            "generated_at": _utc_now(),
            "period": period,
            "window_hours": window_hours,
            "kpis": {
                "coverage_rate": round(float(finding_metrics["coverage_rate"]), 4),
                "false_positive_rate": round(float(finding_metrics["false_positive_rate"]), 4),
                "reproducibility_rate": round(float(reproducibility_metrics["reproducibility_rate"]), 4),
                "closure_cycle_seconds_avg": closure_metrics["closure_cycle_seconds_avg"],
                "single_task_cost_usd_avg": round(float(cost.get("avg_estimated_cost_per_task_usd", 0.0)), 8),
                "approval_lead_time_seconds_avg": approval_metrics["approval_lead_time_seconds_avg"],
            },
            "details": {
                "reliability": reliability,
                "cost": cost,
                "finding_metrics": finding_metrics,
                "reproducibility_metrics": reproducibility_metrics,
                "closure_metrics": closure_metrics,
                "approval_metrics": approval_metrics,
            },
        }

    def export_summary(self, *, period: Period) -> dict[str, Any]:
        summary = self.generate_summary(period=period)
        date_part = str(summary.get("generated_at", _utc_now()))[:10]
        run_id = f"{period}-{datetime.now(UTC).strftime('%Y%m%d%H%M%S%f')}"
        folder = Path(self.settings.output_dir) / date_part / run_id
        folder.mkdir(parents=True, exist_ok=True)

        json_path = folder / "kpi_summary.json"
        md_path = folder / "kpi_summary.md"
        json_path.write_text(json.dumps(summary, ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        md_path.write_text(self._to_markdown(summary), encoding="utf-8")
        return {
            "period": period,
            "summary": summary,
            "artifacts": {
                "json_path": json_path.as_posix(),
                "markdown_path": md_path.as_posix(),
            },
        }

    def _window_hours(self, period: Period) -> int:
        if period == "weekly":
            return max(1, int(self.settings.weekly_window_hours))
        return max(1, int(self.settings.monthly_window_hours))

    def _finding_metrics(self, *, window_hours: int) -> dict[str, Any]:
        tasks = self._load_task_timelines(window_hours=window_hours)
        total_tasks = len(tasks)
        tasks_with_findings = 0
        total_findings = 0
        total_verified = 0

        for snapshots in tasks.values():
            latest = snapshots[-1]
            state = latest.get("state", {})
            if not isinstance(state, dict):
                continue
            scan = state.get("scan", {})
            verification = state.get("verification", {})
            finding_count = int(scan.get("finding_count", 0)) if isinstance(scan, dict) else 0
            verified = int(verification.get("verified_findings", 0)) if isinstance(verification, dict) else 0
            if finding_count > 0:
                tasks_with_findings += 1
            total_findings += max(finding_count, 0)
            total_verified += max(min(verified, finding_count), 0)

        coverage_rate = (tasks_with_findings / total_tasks) if total_tasks else 0.0
        false_positive_rate = (
            (max(total_findings - total_verified, 0) / total_findings)
            if total_findings
            else 0.0
        )
        return {
            "total_tasks": total_tasks,
            "tasks_with_findings": tasks_with_findings,
            "total_findings": total_findings,
            "verified_findings": total_verified,
            "coverage_rate": coverage_rate,
            "false_positive_rate": false_positive_rate,
        }

    def _reproducibility_metrics(self, *, window_hours: int) -> dict[str, Any]:
        tasks = self._load_task_timelines(window_hours=window_hours)
        retest_total = 0
        reproduced_total = 0

        for snapshots in tasks.values():
            latest = snapshots[-1]
            state = latest.get("state", {})
            if not isinstance(state, dict):
                continue
            source_task_id = str(state.get("source_task_id", "")).strip()
            if not source_task_id:
                continue
            retest_total += 1
            diff_report = state.get("diff_report", {})
            summary = diff_report.get("summary", {}) if isinstance(diff_report, dict) else {}
            persistent = int(summary.get("persistent_count", 0)) if isinstance(summary, dict) else 0
            if persistent > 0:
                reproduced_total += 1

        rate = (reproduced_total / retest_total) if retest_total else 0.0
        return {
            "retest_total": retest_total,
            "reproduced_total": reproduced_total,
            "reproducibility_rate": rate,
        }

    def _closure_cycle_metrics(self, *, window_hours: int) -> dict[str, Any]:
        tasks = self._load_task_timelines(window_hours=window_hours)
        deltas: list[float] = []

        for snapshots in tasks.values():
            latest = snapshots[-1]
            state = latest.get("state", {})
            if not isinstance(state, dict):
                continue
            source_task_id = str(state.get("source_task_id", "")).strip()
            if not source_task_id:
                continue
            if str(latest.get("status", "")).lower() != "completed":
                continue
            source = self.state_store.list_snapshots(source_task_id)
            if not source:
                continue
            source_start = _parse_datetime(str(source[0].get("timestamp", "")))
            retest_end = _parse_datetime(str(latest.get("timestamp", "")))
            if source_start is None or retest_end is None:
                continue
            delta = (retest_end - source_start).total_seconds()
            if delta >= 0:
                deltas.append(delta)

        avg_delta = round(sum(deltas) / len(deltas), 2) if deltas else None
        return {
            "samples": len(deltas),
            "closure_cycle_seconds_avg": avg_delta,
        }

    def _approval_metrics(self, *, window_hours: int) -> dict[str, Any]:
        index_path = Path(self.settings.evidence_root) / "audit-events.jsonl"
        if not index_path.exists():
            return {
                "approval_requests": 0,
                "approval_decisions": 0,
                "latency_samples": 0,
                "approval_lead_time_seconds_avg": None,
            }

        cutoff = datetime.now(UTC) - timedelta(hours=max(1, window_hours))
        requests: dict[str, datetime] = {}
        decisions: dict[str, datetime] = {}

        with index_path.open("r", encoding="utf-8") as file_obj:
            for raw in file_obj:
                line = raw.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(event, dict):
                    continue
                ts = _parse_datetime(str(event.get("timestamp", "")))
                if ts is None or ts < cutoff:
                    continue

                action = str(event.get("action", "")).strip()
                reason = str(event.get("reason", "")).strip()
                evidence_dir = str(event.get("evidence_dir", "")).strip()
                if not evidence_dir:
                    continue
                output_payload = _read_output_payload(evidence_dir)
                approval_id = str(output_payload.get("approval_id", "")).strip()
                if not approval_id:
                    continue

                if action == "validate_action" and reason in {"approval_required", "approval_pending"}:
                    previous = requests.get(approval_id)
                    if previous is None or ts < previous:
                        requests[approval_id] = ts
                if action == "approval_decision":
                    previous = decisions.get(approval_id)
                    if previous is None or ts < previous:
                        decisions[approval_id] = ts

        latencies = []
        for approval_id, req_ts in requests.items():
            decision_ts = decisions.get(approval_id)
            if decision_ts is None:
                continue
            delta = (decision_ts - req_ts).total_seconds()
            if delta >= 0:
                latencies.append(delta)

        avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else None
        return {
            "approval_requests": len(requests),
            "approval_decisions": len(decisions),
            "latency_samples": len(latencies),
            "approval_lead_time_seconds_avg": avg_latency,
        }

    def _load_task_timelines(self, *, window_hours: int) -> dict[str, list[dict[str, Any]]]:
        cutoff = datetime.now(UTC) - timedelta(hours=max(1, window_hours))
        result: dict[str, list[dict[str, Any]]] = {}
        base_dir = Path(self.state_store.base_dir)
        if not base_dir.exists():
            return result
        for item in base_dir.iterdir():
            if not item.is_dir():
                continue
            snapshots = self.state_store.list_snapshots(item.name)
            if not snapshots:
                continue
            latest_ts = _parse_datetime(str(snapshots[-1].get("timestamp", "")))
            if latest_ts is None or latest_ts < cutoff:
                continue
            result[item.name] = snapshots
        return result

    @staticmethod
    def _to_markdown(summary: dict[str, Any]) -> str:
        kpi = summary.get("kpis", {})
        lines = [
            f"# KPI Summary ({summary.get('period', '')})",
            "",
            f"- Generated At: {summary.get('generated_at', '')}",
            f"- Window Hours: {summary.get('window_hours', 0)}",
            "",
            "## KPI Values",
            "",
            f"- Coverage Rate: {kpi.get('coverage_rate', 0)}",
            f"- False Positive Rate: {kpi.get('false_positive_rate', 0)}",
            f"- Reproducibility Rate: {kpi.get('reproducibility_rate', 0)}",
            f"- Closure Cycle Seconds Avg: {kpi.get('closure_cycle_seconds_avg')}",
            f"- Single Task Cost USD Avg: {kpi.get('single_task_cost_usd_avg', 0)}",
            f"- Approval Lead Time Seconds Avg: {kpi.get('approval_lead_time_seconds_avg')}",
            "",
            "## Details",
            "",
            "```json",
            json.dumps(summary.get("details", {}), ensure_ascii=True, indent=2),
            "```",
        ]
        return "\n".join(lines) + "\n"


def _read_output_payload(evidence_dir: str) -> dict[str, Any]:
    path = Path(evidence_dir) / "output.json"
    if not path.exists():
        return {}
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _parse_datetime(value: str) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@lru_cache(maxsize=1)
def get_kpi_job_settings() -> KPIJobSettings:
    settings = get_settings()
    observability = settings.get("observability", {})
    kpi = observability.get("kpi", {})
    audit = settings.get("audit", {})
    return KPIJobSettings(
        output_dir=str(kpi.get("output_dir", "observability/kpi")),
        evidence_root=str(audit.get("evidence_root", "evidence")),
        weekly_window_hours=int(kpi.get("weekly_window_hours", 24 * 7)),
        monthly_window_hours=int(kpi.get("monthly_window_hours", 24 * 30)),
    )


@lru_cache(maxsize=1)
def get_kpi_job_service() -> KPIJobService:
    return KPIJobService(
        state_store=get_workflow_state_store(),
        metrics_service=get_workflow_metrics_service(),
        settings=get_kpi_job_settings(),
    )


def clear_kpi_caches() -> None:
    get_kpi_job_settings.cache_clear()
    get_kpi_job_service.cache_clear()
