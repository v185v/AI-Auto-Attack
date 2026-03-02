from fastapi.testclient import TestClient

from backend.api.workflows import (
    workflow_temporal_client_dep,
    workflow_temporal_settings_dep,
)
from backend.main import app
from backend.workflow.temporal_worker import TemporalSettings


class StubTemporalClient:
    async def start_poc_workflow(self, payload, workflow_id=None):
        return {
            "accepted": True,
            "mode": "temporal",
            "workflow_id": workflow_id or "wf-123",
            "run_id": "run-123",
            "task_queue": "ai-attack-task-queue",
        }

    async def describe_workflow(self, workflow_id, run_id=None):
        return {"workflow_id": workflow_id, "run_id": run_id or "run-123", "status": "running"}

    async def get_result(self, workflow_id, run_id=None):
        return {"status": "completed", "report": {"summary": {"target": "10.20.1.8"}}}

    async def cancel_workflow(self, workflow_id, run_id=None):
        return {"workflow_id": workflow_id, "run_id": run_id, "status": "cancel_requested"}


def _enabled_settings() -> TemporalSettings:
    return TemporalSettings(
        enabled=True,
        address="localhost:7233",
        namespace="default",
        task_queue="ai-attack-task-queue",
        workflow_id_prefix="ai-attack-poc",
        execution_timeout_seconds=3600,
        run_timeout_seconds=3600,
        activity_start_to_close_timeout_seconds=1200,
        activity_schedule_to_close_timeout_seconds=1800,
        retry_max_attempts=3,
        retry_initial_interval_seconds=2,
        retry_max_interval_seconds=30,
        retry_backoff_coefficient=2.0,
    )


def _disabled_settings() -> TemporalSettings:
    data = _enabled_settings()
    return TemporalSettings(**{**data.__dict__, "enabled": False})


def test_temporal_async_workflow_endpoints_with_stub_client() -> None:
    app.dependency_overrides[workflow_temporal_settings_dep] = _enabled_settings
    app.dependency_overrides[workflow_temporal_client_dep] = lambda: StubTemporalClient()
    try:
        client = TestClient(app)
        start = client.post("/workflows/poc/start", json={"target": "10.20.1.8", "requested_by": "tester"})
        assert start.status_code == 200
        start_body = start.json()
        assert start_body["accepted"] is True
        workflow_id = start_body["workflow_id"]

        status = client.get(f"/workflows/poc/status/{workflow_id}")
        assert status.status_code == 200
        assert status.json()["status"] == "running"

        result = client.get(f"/workflows/poc/result/{workflow_id}")
        assert result.status_code == 200
        assert result.json()["status"] == "completed"

        cancel = client.post(f"/workflows/poc/cancel/{workflow_id}")
        assert cancel.status_code == 200
        assert cancel.json()["status"] == "cancel_requested"
    finally:
        app.dependency_overrides.clear()


def test_temporal_endpoints_return_503_when_disabled() -> None:
    app.dependency_overrides[workflow_temporal_settings_dep] = _disabled_settings
    app.dependency_overrides[workflow_temporal_client_dep] = lambda: StubTemporalClient()
    try:
        client = TestClient(app)
        start = client.post("/workflows/poc/start", json={"target": "10.20.1.8", "requested_by": "tester"})
        assert start.status_code == 503
        assert start.json()["detail"]["reason"] == "temporal_disabled"
    finally:
        app.dependency_overrides.clear()

