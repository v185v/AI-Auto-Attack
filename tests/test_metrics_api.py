from fastapi.testclient import TestClient

from backend.api.metrics import kpi_job_dep, workflow_metrics_dep
from backend.main import app


class StubMetricsService:
    def summarize(self, *, window_hours=None):
        return {
            "generated_at": "2026-03-01T00:00:00+00:00",
            "window_hours": window_hours or 168,
            "total_tasks": 10,
            "failed_tasks": 2,
            "failure_rate": 0.2,
            "error_budget": {"status": "healthy", "breached": False, "breaches": []},
        }

    def list_failures(self, *, window_hours=None, limit=50):
        return {
            "generated_at": "2026-03-01T00:00:00+00:00",
            "window_hours": window_hours or 168,
            "total": 1,
            "limit": limit,
            "items": [
                {
                    "task_id": "task-1",
                    "trace_id": "trace-1",
                    "step": "scan_target",
                    "failure_reason": "scan_execution_failed:all_tools_failed",
                    "error": {"code": "TOOL_EXECUTION_FAILED"},
                    "failed_at": "2026-03-01T00:00:00+00:00",
                    "latest_status": "failed",
                    "recovered": False,
                }
            ],
        }

    def summarize_cost(self, *, window_hours=None):
        return {
            "generated_at": "2026-03-01T00:00:00+00:00",
            "window_hours": window_hours or 168,
            "total_tasks": 2,
            "llm_calls": 3,
            "cache_hits": 1,
            "cache_hit_rate": 0.3333,
            "total_estimated_cost_usd": 0.1234,
            "avg_estimated_cost_per_task_usd": 0.0617,
            "avg_llm_latency_ms": 250.0,
            "per_model": [],
            "budget": {"status": "healthy", "breached": False, "breaches": []},
        }


class StubKPIJobService:
    def generate_summary(self, *, period="weekly"):
        return {
            "generated_at": "2026-03-02T00:00:00+00:00",
            "period": period,
            "window_hours": 168 if period == "weekly" else 720,
            "kpis": {
                "coverage_rate": 0.8,
                "false_positive_rate": 0.2,
                "reproducibility_rate": 0.6,
                "closure_cycle_seconds_avg": 1800.0,
                "single_task_cost_usd_avg": 0.05,
                "approval_lead_time_seconds_avg": 120.0,
            },
            "details": {},
        }

    def export_summary(self, *, period="weekly"):
        return {
            "period": period,
            "summary": self.generate_summary(period=period),
            "artifacts": {
                "json_path": "observability/kpi/2026-03-02/weekly-1/kpi_summary.json",
                "markdown_path": "observability/kpi/2026-03-02/weekly-1/kpi_summary.md",
            },
        }

def test_metrics_api_summary_and_failures() -> None:
    app.dependency_overrides[workflow_metrics_dep] = lambda: StubMetricsService()
    app.dependency_overrides[kpi_job_dep] = lambda: StubKPIJobService()
    try:
        client = TestClient(app)

        summary = client.get("/metrics/workflows/summary", params={"window_hours": 24})
        assert summary.status_code == 200
        summary_body = summary.json()
        assert summary_body["window_hours"] == 24
        assert summary_body["failure_rate"] == 0.2

        failures = client.get("/metrics/workflows/failures", params={"window_hours": 24, "limit": 5})
        assert failures.status_code == 200
        failures_body = failures.json()
        assert failures_body["window_hours"] == 24
        assert failures_body["limit"] == 5
        assert failures_body["items"][0]["error"]["code"] == "TOOL_EXECUTION_FAILED"

        cost = client.get("/metrics/workflows/cost", params={"window_hours": 24})
        assert cost.status_code == 200
        cost_body = cost.json()
        assert cost_body["window_hours"] == 24
        assert cost_body["llm_calls"] == 3
        assert cost_body["total_estimated_cost_usd"] == 0.1234

        kpi_summary = client.get("/metrics/kpi/summary", params={"period": "weekly"})
        assert kpi_summary.status_code == 200
        kpi_summary_body = kpi_summary.json()
        assert kpi_summary_body["period"] == "weekly"
        assert kpi_summary_body["kpis"]["coverage_rate"] == 0.8

        kpi_export = client.post("/metrics/kpi/export", params={"period": "monthly"})
        assert kpi_export.status_code == 200
        kpi_export_body = kpi_export.json()
        assert kpi_export_body["period"] == "monthly"
        assert kpi_export_body["artifacts"]["json_path"].endswith("kpi_summary.json")
    finally:
        app.dependency_overrides.clear()
