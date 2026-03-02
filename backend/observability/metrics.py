from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

from backend.core.config import get_settings
from backend.workflow.state_store import WorkflowStateStore, get_workflow_state_store


@dataclass(frozen=True)
class ErrorBudgetSettings:
    max_failure_rate: float
    min_retry_success_rate: float
    max_mttr_seconds: int
    default_window_hours: int


@dataclass(frozen=True)
class CostControlSettings:
    max_per_task_usd: float
    max_llm_latency_ms: int
    default_window_hours: int


@dataclass(frozen=True)
class FailureClassification:
    code: str
    category: str
    severity: str
    retriable: bool
    description: str


_FAILURE_TAXONOMY: list[tuple[str, FailureClassification]] = [
    (
        "scope_denied:",
        FailureClassification(
            code="POLICY_SCOPE_DENIED",
            category="policy",
            severity="high",
            retriable=False,
            description="Target blocked by scope policy.",
        ),
    ),
    (
        "action_denied:",
        FailureClassification(
            code="POLICY_ACTION_DENIED",
            category="policy",
            severity="high",
            retriable=False,
            description="Action blocked by action gate policy.",
        ),
    ),
    (
        "scan_execution_failed:",
        FailureClassification(
            code="TOOL_EXECUTION_FAILED",
            category="tool",
            severity="high",
            retriable=True,
            description="Security tool execution failed during scan stage.",
        ),
    ),
    (
        "temporal_execution_failed:",
        FailureClassification(
            code="WORKFLOW_ORCHESTRATION_FAILED",
            category="workflow",
            severity="critical",
            retriable=True,
            description="Workflow orchestration engine failed.",
        ),
    ),
    (
        "invalid_activity_result",
        FailureClassification(
            code="WORKFLOW_INVALID_RESULT",
            category="workflow",
            severity="high",
            retriable=False,
            description="Workflow activity returned invalid payload.",
        ),
    ),
    (
        "invalid_temporal_result",
        FailureClassification(
            code="WORKFLOW_INVALID_RESULT",
            category="workflow",
            severity="high",
            retriable=False,
            description="Temporal workflow result payload is invalid.",
        ),
    ),
    (
        "llm_timeout",
        FailureClassification(
            code="MODEL_TIMEOUT",
            category="model",
            severity="medium",
            retriable=True,
            description="LLM request timed out.",
        ),
    ),
    (
        "llm_provider_error",
        FailureClassification(
            code="MODEL_PROVIDER_ERROR",
            category="model",
            severity="medium",
            retriable=True,
            description="LLM provider request failed.",
        ),
    ),
    (
        "network_timeout",
        FailureClassification(
            code="NETWORK_TIMEOUT",
            category="network",
            severity="medium",
            retriable=True,
            description="Network timeout during task execution.",
        ),
    ),
]

_UNKNOWN_FAILURE = FailureClassification(
    code="UNKNOWN_FAILURE",
    category="unknown",
    severity="medium",
    retriable=True,
    description="Failure reason is not categorized yet.",
)


def classify_failure(reason: str, step: str | None = None) -> dict[str, Any]:
    normalized = reason.strip().lower()
    if not normalized:
        return {
            "code": "NONE",
            "category": "none",
            "severity": "none",
            "retriable": False,
            "description": "No failure.",
            "step": step or "",
            "reason": "",
        }
    for pattern, classification in _FAILURE_TAXONOMY:
        if normalized.startswith(pattern) or pattern in normalized:
            return {
                "code": classification.code,
                "category": classification.category,
                "severity": classification.severity,
                "retriable": classification.retriable,
                "description": classification.description,
                "step": step or "",
                "reason": reason,
            }
    return {
        "code": _UNKNOWN_FAILURE.code,
        "category": _UNKNOWN_FAILURE.category,
        "severity": _UNKNOWN_FAILURE.severity,
        "retriable": _UNKNOWN_FAILURE.retriable,
        "description": _UNKNOWN_FAILURE.description,
        "step": step or "",
        "reason": reason,
    }


class WorkflowMetricsService:
    def __init__(
        self,
        state_store: WorkflowStateStore,
        settings: ErrorBudgetSettings,
        cost_settings: CostControlSettings,
    ) -> None:
        self.state_store = state_store
        self.settings = settings
        self.cost_settings = cost_settings

    def summarize(self, *, window_hours: int | None = None) -> dict[str, Any]:
        effective_window = int(window_hours or self.settings.default_window_hours)
        tasks = self._load_task_timelines(window_hours=effective_window)

        total_tasks = len(tasks)
        completed_tasks = 0
        failed_tasks = 0
        in_progress_tasks = 0
        tasks_with_failures = 0
        recovered_tasks = 0
        mttr_samples: list[float] = []
        terminal_error_counts: dict[str, int] = {}

        for snapshots in tasks.values():
            latest = snapshots[-1]
            latest_status = str(latest.get("status", "unknown"))
            if latest_status == "completed":
                completed_tasks += 1
            elif latest_status == "failed":
                failed_tasks += 1
                reason = _extract_failure_reason(latest)
                classification = classify_failure(reason, str(latest.get("step", "")))
                code = str(classification["code"])
                terminal_error_counts[code] = terminal_error_counts.get(code, 0) + 1
            else:
                in_progress_tasks += 1

            first_failure, first_recovery = _find_failure_and_recovery(snapshots)
            if first_failure is not None:
                tasks_with_failures += 1
            if first_failure is not None and first_recovery is not None:
                recovered_tasks += 1
                delta = (first_recovery - first_failure).total_seconds()
                if delta >= 0:
                    mttr_samples.append(delta)

        failure_rate = (failed_tasks / total_tasks) if total_tasks else 0.0
        retry_success_rate = (
            recovered_tasks / tasks_with_failures if tasks_with_failures else 1.0
        )
        mttr_seconds_avg = (
            sum(mttr_samples) / len(mttr_samples) if mttr_samples else None
        )
        budget = self._evaluate_error_budget(
            failure_rate=failure_rate,
            retry_success_rate=retry_success_rate,
            mttr_seconds_avg=mttr_seconds_avg,
        )

        top_errors = []
        for code, count in sorted(
            terminal_error_counts.items(), key=lambda item: item[1], reverse=True
        ):
            classification = _classification_for_code(code)
            top_errors.append(
                {
                    "code": code,
                    "count": count,
                    "category": classification["category"],
                    "severity": classification["severity"],
                }
            )

        return {
            "generated_at": _utc_now(),
            "window_hours": effective_window,
            "total_tasks": total_tasks,
            "completed_tasks": completed_tasks,
            "failed_tasks": failed_tasks,
            "in_progress_tasks": in_progress_tasks,
            "failure_rate": round(failure_rate, 4),
            "tasks_with_failures": tasks_with_failures,
            "recovered_tasks": recovered_tasks,
            "retry_success_rate": round(retry_success_rate, 4),
            "mttr_seconds_avg": round(mttr_seconds_avg, 2) if mttr_seconds_avg is not None else None,
            "top_errors": top_errors,
            "error_budget": budget,
        }

    def list_failures(
        self,
        *,
        window_hours: int | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        effective_window = int(window_hours or self.settings.default_window_hours)
        tasks = self._load_task_timelines(window_hours=effective_window)
        items: list[dict[str, Any]] = []

        for task_id, snapshots in tasks.items():
            failed_snapshots = [item for item in snapshots if str(item.get("status", "")) == "failed"]
            if not failed_snapshots:
                continue
            failed = failed_snapshots[-1]
            latest = snapshots[-1]
            reason = _extract_failure_reason(failed)
            classification = classify_failure(reason, str(failed.get("step", "")))
            failed_at = _parse_datetime(str(failed.get("timestamp", "")))
            latest_at = _parse_datetime(str(latest.get("timestamp", "")))
            recovered = (
                str(latest.get("status", "")) == "completed"
                and failed_at is not None
                and latest_at is not None
                and latest_at >= failed_at
            )
            items.append(
                {
                    "task_id": task_id,
                    "trace_id": str(failed.get("trace_id", "")),
                    "step": str(failed.get("step", "")),
                    "failure_reason": reason,
                    "error": classification,
                    "failed_at": str(failed.get("timestamp", "")),
                    "latest_status": str(latest.get("status", "")),
                    "recovered": recovered,
                }
            )

        items.sort(key=lambda item: item.get("failed_at", ""), reverse=True)
        sliced = items[: max(1, limit)]
        return {
            "generated_at": _utc_now(),
            "window_hours": effective_window,
            "total": len(items),
            "limit": max(1, limit),
            "items": sliced,
        }

    def summarize_cost(self, *, window_hours: int | None = None) -> dict[str, Any]:
        effective_window = int(window_hours or self.cost_settings.default_window_hours)
        tasks = self._load_task_timelines(window_hours=effective_window)
        total_tasks = len(tasks)
        llm_calls = 0
        cache_hits = 0
        total_cost_usd = 0.0
        latency_samples: list[int] = []
        per_model: dict[str, dict[str, Any]] = {}

        for snapshots in tasks.values():
            for snapshot in snapshots:
                if str(snapshot.get("step", "")) != "llm_decide":
                    continue
                state = snapshot.get("state", {})
                if not isinstance(state, dict):
                    continue
                llm_decision = state.get("llm_decision", {})
                if not isinstance(llm_decision, dict) or not llm_decision:
                    continue
                runtime = llm_decision.get("llm_runtime", {})
                if not isinstance(runtime, dict):
                    continue
                if not bool(runtime.get("attempted", True)):
                    continue

                llm_calls += 1
                cache_hit = bool(runtime.get("cache_hit", False))
                if cache_hit:
                    cache_hits += 1

                model = str(llm_decision.get("model", "unknown"))
                estimated_cost = float(runtime.get("estimated_cost_usd", 0.0))
                latency_ms = int(runtime.get("latency_ms", 0))
                total_cost_usd += estimated_cost
                if latency_ms > 0:
                    latency_samples.append(latency_ms)

                model_row = per_model.setdefault(
                    model,
                    {
                        "model": model,
                        "calls": 0,
                        "cache_hits": 0,
                        "estimated_cost_usd": 0.0,
                        "latency_ms_samples": [],
                    },
                )
                model_row["calls"] += 1
                if cache_hit:
                    model_row["cache_hits"] += 1
                model_row["estimated_cost_usd"] = round(float(model_row["estimated_cost_usd"]) + estimated_cost, 8)
                if latency_ms > 0:
                    model_row["latency_ms_samples"].append(latency_ms)

        per_model_rows: list[dict[str, Any]] = []
        for row in per_model.values():
            samples = list(row.pop("latency_ms_samples", []))
            calls = int(row.get("calls", 0))
            cache_hits_per_model = int(row.get("cache_hits", 0))
            row["cache_hit_rate"] = round((cache_hits_per_model / calls), 4) if calls else 0.0
            row["avg_latency_ms"] = round(sum(samples) / len(samples), 2) if samples else None
            per_model_rows.append(row)
        per_model_rows.sort(key=lambda item: float(item.get("estimated_cost_usd", 0.0)), reverse=True)

        avg_latency_ms = round(sum(latency_samples) / len(latency_samples), 2) if latency_samples else 0.0
        avg_cost_per_task = round((total_cost_usd / total_tasks), 8) if total_tasks else 0.0
        budget = self._evaluate_cost_budget(avg_cost_per_task=avg_cost_per_task, avg_latency_ms=avg_latency_ms)
        return {
            "generated_at": _utc_now(),
            "window_hours": effective_window,
            "total_tasks": total_tasks,
            "llm_calls": llm_calls,
            "cache_hits": cache_hits,
            "cache_hit_rate": round((cache_hits / llm_calls), 4) if llm_calls else 0.0,
            "total_estimated_cost_usd": round(total_cost_usd, 8),
            "avg_estimated_cost_per_task_usd": avg_cost_per_task,
            "avg_llm_latency_ms": avg_latency_ms,
            "per_model": per_model_rows,
            "budget": budget,
        }

    def _load_task_timelines(self, *, window_hours: int) -> dict[str, list[dict[str, Any]]]:
        cutoff = datetime.now(UTC) - timedelta(hours=max(1, window_hours))
        result: dict[str, list[dict[str, Any]]] = {}
        for task_id in self._list_task_ids():
            snapshots = self.state_store.list_snapshots(task_id)
            if not snapshots:
                continue
            latest_ts = _parse_datetime(str(snapshots[-1].get("timestamp", "")))
            if latest_ts is None or latest_ts < cutoff:
                continue
            result[task_id] = snapshots
        return result

    def _list_task_ids(self) -> list[str]:
        base_dir = Path(self.state_store.base_dir)
        if not base_dir.exists():
            return []
        return sorted([item.name for item in base_dir.iterdir() if item.is_dir()])

    def _evaluate_error_budget(
        self,
        *,
        failure_rate: float,
        retry_success_rate: float,
        mttr_seconds_avg: float | None,
    ) -> dict[str, Any]:
        breaches: list[dict[str, Any]] = []

        if failure_rate > self.settings.max_failure_rate:
            breaches.append(
                {
                    "metric": "failure_rate",
                    "actual": round(failure_rate, 4),
                    "target": self.settings.max_failure_rate,
                }
            )
        if retry_success_rate < self.settings.min_retry_success_rate:
            breaches.append(
                {
                    "metric": "retry_success_rate",
                    "actual": round(retry_success_rate, 4),
                    "target": self.settings.min_retry_success_rate,
                }
            )
        if mttr_seconds_avg is not None and mttr_seconds_avg > float(self.settings.max_mttr_seconds):
            breaches.append(
                {
                    "metric": "mttr_seconds_avg",
                    "actual": round(mttr_seconds_avg, 2),
                    "target": self.settings.max_mttr_seconds,
                }
            )
        return {
            "status": "breached" if breaches else "healthy",
            "breached": bool(breaches),
            "breaches": breaches,
            "targets": {
                "max_failure_rate": self.settings.max_failure_rate,
                "min_retry_success_rate": self.settings.min_retry_success_rate,
                "max_mttr_seconds": self.settings.max_mttr_seconds,
            },
        }

    def _evaluate_cost_budget(self, *, avg_cost_per_task: float, avg_latency_ms: float) -> dict[str, Any]:
        breaches = []
        if avg_cost_per_task > self.cost_settings.max_per_task_usd:
            breaches.append(
                {
                    "metric": "avg_estimated_cost_per_task_usd",
                    "actual": round(avg_cost_per_task, 8),
                    "target": self.cost_settings.max_per_task_usd,
                }
            )
        if avg_latency_ms > float(self.cost_settings.max_llm_latency_ms):
            breaches.append(
                {
                    "metric": "avg_llm_latency_ms",
                    "actual": round(avg_latency_ms, 2),
                    "target": self.cost_settings.max_llm_latency_ms,
                }
            )
        return {
            "status": "breached" if breaches else "healthy",
            "breached": bool(breaches),
            "breaches": breaches,
            "targets": {
                "max_per_task_usd": self.cost_settings.max_per_task_usd,
                "max_llm_latency_ms": self.cost_settings.max_llm_latency_ms,
            },
        }


def _extract_failure_reason(snapshot: dict[str, Any]) -> str:
    state = snapshot.get("state", {})
    if isinstance(state, dict):
        state_reason = str(state.get("failure_reason", "")).strip()
        if state_reason:
            return state_reason
    reason = str(snapshot.get("reason", "")).strip()
    return reason or "unknown_failure"


def _find_failure_and_recovery(
    snapshots: list[dict[str, Any]],
) -> tuple[datetime | None, datetime | None]:
    first_failure: datetime | None = None
    first_recovery: datetime | None = None
    for item in snapshots:
        status = str(item.get("status", ""))
        timestamp = _parse_datetime(str(item.get("timestamp", "")))
        if timestamp is None:
            continue
        if status == "failed" and first_failure is None:
            first_failure = timestamp
        if first_failure is not None and status == "completed":
            first_recovery = timestamp
            break
    return first_failure, first_recovery


def _classification_for_code(code: str) -> dict[str, Any]:
    for _, classification in _FAILURE_TAXONOMY:
        if classification.code == code:
            return {
                "code": classification.code,
                "category": classification.category,
                "severity": classification.severity,
                "retriable": classification.retriable,
                "description": classification.description,
            }
    return {
        "code": _UNKNOWN_FAILURE.code,
        "category": _UNKNOWN_FAILURE.category,
        "severity": _UNKNOWN_FAILURE.severity,
        "retriable": _UNKNOWN_FAILURE.retriable,
        "description": _UNKNOWN_FAILURE.description,
    }


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
def get_error_budget_settings() -> ErrorBudgetSettings:
    settings = get_settings()
    observability = settings.get("observability", {})
    error_budget = observability.get("error_budget", {})
    return ErrorBudgetSettings(
        max_failure_rate=float(error_budget.get("max_failure_rate", 0.2)),
        min_retry_success_rate=float(error_budget.get("min_retry_success_rate", 0.6)),
        max_mttr_seconds=int(error_budget.get("max_mttr_seconds", 1800)),
        default_window_hours=int(observability.get("default_window_hours", 168)),
    )


@lru_cache(maxsize=1)
def get_cost_control_settings() -> CostControlSettings:
    settings = get_settings()
    observability = settings.get("observability", {})
    llm = settings.get("llm", {})
    cost = llm.get("cost", {})
    return CostControlSettings(
        max_per_task_usd=float(cost.get("max_per_task_usd", 1.0)),
        max_llm_latency_ms=int(cost.get("max_llm_latency_ms", 15000)),
        default_window_hours=int(observability.get("default_window_hours", 168)),
    )


@lru_cache(maxsize=1)
def get_workflow_metrics_service() -> WorkflowMetricsService:
    return WorkflowMetricsService(
        state_store=get_workflow_state_store(),
        settings=get_error_budget_settings(),
        cost_settings=get_cost_control_settings(),
    )


def clear_metrics_caches() -> None:
    get_error_budget_settings.cache_clear()
    get_cost_control_settings.cache_clear()
    get_workflow_metrics_service.cache_clear()
