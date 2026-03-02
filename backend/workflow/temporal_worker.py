from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import timedelta
from functools import lru_cache
from typing import Any
from uuid import uuid4

from temporalio import activity, workflow
from temporalio.client import Client
from temporalio.common import RetryPolicy
from temporalio.worker import Worker

from agents.workflow_graph import run_poc_workflow
from backend.core.config import get_settings
from backend.workflow.state_store import get_workflow_state_store


@dataclass(frozen=True)
class TemporalSettings:
    enabled: bool
    address: str
    namespace: str
    task_queue: str
    workflow_id_prefix: str
    execution_timeout_seconds: int
    run_timeout_seconds: int
    activity_start_to_close_timeout_seconds: int
    activity_schedule_to_close_timeout_seconds: int
    retry_max_attempts: int
    retry_initial_interval_seconds: int
    retry_max_interval_seconds: int
    retry_backoff_coefficient: float


@activity.defn
async def execute_poc_workflow_activity(payload: dict[str, Any]) -> dict[str, Any]:
    target = str(payload.get("target", "")).strip()
    requested_by = str(payload.get("requested_by", "system"))
    trace_id = payload.get("trace_id")
    task_id = payload.get("task_id")
    agent_id = str(payload.get("agent_id", "workflow-p2-temporal"))
    # Run existing graph as activity body; retry policy is handled by Temporal.
    return run_poc_workflow(
        target=target,
        requested_by=requested_by,
        trace_id=trace_id,
        task_id=task_id,
        agent_id=agent_id,
        state_store=get_workflow_state_store(),
    )


@activity.defn
async def compensate_poc_workflow_activity(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "compensated": True,
        "action": "mark_workflow_failed",
        "target": payload.get("target"),
        "reason": payload.get("reason", "unknown"),
    }


@workflow.defn(name="poc-single-target-workflow")
class PocSingleTargetTemporalWorkflow:
    @workflow.run
    async def run(self, payload: dict[str, Any]) -> dict[str, Any]:
        settings = get_temporal_settings()
        retry_policy = build_retry_policy(settings)
        try:
            result = await workflow.execute_activity(
                execute_poc_workflow_activity,
                payload,
                retry_policy=retry_policy,
                start_to_close_timeout=timedelta(seconds=settings.activity_start_to_close_timeout_seconds),
                schedule_to_close_timeout=timedelta(seconds=settings.activity_schedule_to_close_timeout_seconds),
            )
            if isinstance(result, dict):
                return result
            return {"status": "failed", "failure_reason": "invalid_activity_result"}
        except Exception as exc:
            compensation = await workflow.execute_activity(
                compensate_poc_workflow_activity,
                {
                    "target": payload.get("target"),
                    "reason": f"activity_failed:{exc}",
                },
                start_to_close_timeout=timedelta(seconds=30),
                schedule_to_close_timeout=timedelta(seconds=60),
            )
            return {
                "status": "failed",
                "failure_reason": f"temporal_execution_failed:{exc}",
                "compensation": compensation,
            }


def build_retry_policy(settings: TemporalSettings) -> RetryPolicy:
    return RetryPolicy(
        initial_interval=timedelta(seconds=settings.retry_initial_interval_seconds),
        maximum_interval=timedelta(seconds=settings.retry_max_interval_seconds),
        backoff_coefficient=settings.retry_backoff_coefficient,
        maximum_attempts=settings.retry_max_attempts,
    )


class TemporalWorkflowClient:
    def __init__(self, settings: TemporalSettings, client: Client | None = None) -> None:
        self.settings = settings
        self._client = client

    async def start_poc_workflow(self, payload: dict[str, Any], workflow_id: str | None = None) -> dict[str, Any]:
        client = await self._ensure_client()
        wf_id = workflow_id or f"{self.settings.workflow_id_prefix}-{uuid4().hex[:10]}"
        handle = await client.start_workflow(
            PocSingleTargetTemporalWorkflow.run,
            payload,
            id=wf_id,
            task_queue=self.settings.task_queue,
            execution_timeout=timedelta(seconds=self.settings.execution_timeout_seconds),
            run_timeout=timedelta(seconds=self.settings.run_timeout_seconds),
        )
        return {
            "accepted": True,
            "mode": "temporal",
            "workflow_id": handle.id,
            "run_id": handle.result_run_id,
            "task_queue": self.settings.task_queue,
        }

    async def describe_workflow(self, workflow_id: str, run_id: str | None = None) -> dict[str, Any]:
        client = await self._ensure_client()
        handle = client.get_workflow_handle(workflow_id=workflow_id, run_id=run_id)
        description = await handle.describe()
        status = _normalize_status(description)
        return {
            "workflow_id": workflow_id,
            "run_id": _extract_run_id(description),
            "status": status,
        }

    async def get_result(self, workflow_id: str, run_id: str | None = None) -> dict[str, Any]:
        client = await self._ensure_client()
        handle = client.get_workflow_handle(workflow_id=workflow_id, run_id=run_id)
        result = await handle.result()
        if isinstance(result, dict):
            return result
        return {"status": "failed", "failure_reason": "invalid_temporal_result"}

    async def cancel_workflow(self, workflow_id: str, run_id: str | None = None) -> dict[str, Any]:
        client = await self._ensure_client()
        handle = client.get_workflow_handle(workflow_id=workflow_id, run_id=run_id)
        await handle.cancel()
        return {"workflow_id": workflow_id, "run_id": run_id, "status": "cancel_requested"}

    async def _ensure_client(self) -> Client:
        if self._client is None:
            self._client = await Client.connect(
                target_host=self.settings.address,
                namespace=self.settings.namespace,
            )
        return self._client


class TemporalWorkerRunner:
    def __init__(self, settings: TemporalSettings, client: Client | None = None) -> None:
        self.settings = settings
        self.client = client

    async def run(self) -> None:
        client = self.client
        if client is None:
            client = await Client.connect(
                target_host=self.settings.address,
                namespace=self.settings.namespace,
            )
        worker = Worker(
            client,
            task_queue=self.settings.task_queue,
            workflows=[PocSingleTargetTemporalWorkflow],
            activities=[execute_poc_workflow_activity, compensate_poc_workflow_activity],
        )
        await worker.run()


def _normalize_status(description: Any) -> str:
    status_obj = getattr(description, "status", None)
    status_name = getattr(status_obj, "name", str(status_obj or "UNKNOWN"))
    normalized = status_name.replace("WORKFLOW_EXECUTION_STATUS_", "").lower()
    mapping = {
        "running": "running",
        "completed": "completed",
        "failed": "failed",
        "canceled": "canceled",
        "terminated": "terminated",
        "continued_as_new": "continued_as_new",
        "timed_out": "timed_out",
    }
    return mapping.get(normalized, normalized or "unknown")


def _extract_run_id(description: Any) -> str | None:
    try:
        return str(description.execution_info.execution.run_id)
    except Exception:
        return None


@lru_cache(maxsize=1)
def get_temporal_settings() -> TemporalSettings:
    settings = get_settings()
    wf = settings.get("workflow", {})
    temporal = wf.get("temporal", {})
    retry = temporal.get("retry", {})

    return TemporalSettings(
        enabled=bool(temporal.get("enabled", False)),
        address=str(temporal.get("address", "localhost:7233")),
        namespace=str(temporal.get("namespace", "default")),
        task_queue=str(temporal.get("task_queue", "ai-attack-task-queue")),
        workflow_id_prefix=str(temporal.get("workflow_id_prefix", "ai-attack-poc")),
        execution_timeout_seconds=int(temporal.get("execution_timeout_seconds", 3600)),
        run_timeout_seconds=int(temporal.get("run_timeout_seconds", 3600)),
        activity_start_to_close_timeout_seconds=int(
            temporal.get("activity_start_to_close_timeout_seconds", 1200)
        ),
        activity_schedule_to_close_timeout_seconds=int(
            temporal.get("activity_schedule_to_close_timeout_seconds", 1800)
        ),
        retry_max_attempts=int(retry.get("max_attempts", 3)),
        retry_initial_interval_seconds=int(retry.get("initial_interval_seconds", 2)),
        retry_max_interval_seconds=int(retry.get("max_interval_seconds", 30)),
        retry_backoff_coefficient=float(retry.get("backoff_coefficient", 2.0)),
    )


@lru_cache(maxsize=1)
def get_temporal_workflow_client() -> TemporalWorkflowClient:
    return TemporalWorkflowClient(get_temporal_settings())


def clear_temporal_caches() -> None:
    get_temporal_settings.cache_clear()
    get_temporal_workflow_client.cache_clear()


async def run_temporal_worker_forever() -> None:
    settings = get_temporal_settings()
    runner = TemporalWorkerRunner(settings=settings)
    await runner.run()


if __name__ == "__main__":
    asyncio.run(run_temporal_worker_forever())
