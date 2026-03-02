# Retry and Compensation (P2-1)

## Goal

Define a reliable execution strategy for long-running automated security workflows using Temporal.

## Retry Strategy

Activity retries are configured via Temporal `RetryPolicy`:

- `max_attempts`: maximum retry count for activity failures
- `initial_interval_seconds`: first retry delay
- `max_interval_seconds`: maximum backoff interval
- `backoff_coefficient`: exponential backoff multiplier

Current config source:

- `settings.yaml -> workflow.temporal.retry`

## Timeout Strategy

Timeout layers:

1. Workflow execution timeout
   - `execution_timeout_seconds`
2. Workflow run timeout
   - `run_timeout_seconds`
3. Activity start-to-close timeout
   - `activity_start_to_close_timeout_seconds`
4. Activity schedule-to-close timeout
   - `activity_schedule_to_close_timeout_seconds`

These are configured under:

- `settings.yaml -> workflow.temporal`

## Compensation Strategy

When the primary workflow activity fails after retries:

1. Execute compensation activity `compensate_poc_workflow_activity`
2. Return a failed result with:
   - `failure_reason`
   - `compensation` metadata

Compensation currently performs a minimal state marker for failed execution and is designed to be extended with:

- temporary resource cleanup
- lock release
- external ticket rollback or status transition

## Operational Endpoints

- `POST /workflows/poc/start` - submit async workflow execution
- `GET /workflows/poc/status/{workflow_id}` - inspect workflow status
- `GET /workflows/poc/result/{workflow_id}` - get final workflow result
- `POST /workflows/poc/cancel/{workflow_id}` - request cancellation

## Running Temporal Worker

Worker entrypoint:

- `python -m backend.workflow.temporal_worker`

Prerequisites:

1. Temporal server reachable at configured `address`
2. `workflow.temporal.enabled: true`
3. Matching `task_queue` between API client and worker

