# Error Taxonomy and Error Budget (P2-3)

## Purpose

Define a unified failure classification model and measurable reliability targets for workflow operations.

## Classification Dimensions

- `code`: stable machine-readable error code.
- `category`: high-level fault domain (`policy`, `tool`, `workflow`, `model`, `network`, `unknown`).
- `severity`: `critical` / `high` / `medium` / `low`.
- `retriable`: whether retry/resume is expected to help.

## Current Error Codes

| Code | Trigger Pattern | Category | Severity | Retriable | Notes |
|---|---|---|---|---|---|
| `POLICY_SCOPE_DENIED` | `scope_denied:*` | `policy` | `high` | `false` | Unauthorized target blocked by scope guard. |
| `POLICY_ACTION_DENIED` | `action_denied:*` | `policy` | `high` | `false` | Action blocked by action gate policy. |
| `TOOL_EXECUTION_FAILED` | `scan_execution_failed:*` | `tool` | `high` | `true` | One or more scanner tools failed during scan stage. |
| `WORKFLOW_ORCHESTRATION_FAILED` | `temporal_execution_failed:*` | `workflow` | `critical` | `true` | Workflow engine/activity execution failure. |
| `WORKFLOW_INVALID_RESULT` | `invalid_activity_result` / `invalid_temporal_result` | `workflow` | `high` | `false` | Invalid result payload contract. |
| `MODEL_TIMEOUT` | `llm_timeout` | `model` | `medium` | `true` | LLM request timeout. |
| `MODEL_PROVIDER_ERROR` | `llm_provider_error` | `model` | `medium` | `true` | LLM provider/network error. |
| `NETWORK_TIMEOUT` | `network_timeout` | `network` | `medium` | `true` | Transport-level timeout. |
| `UNKNOWN_FAILURE` | fallback | `unknown` | `medium` | `true` | Not yet mapped; should be reviewed and promoted into taxonomy. |

## Metrics Definitions

- `failure_rate`: `failed_tasks / total_tasks`
- `retry_success_rate`: `recovered_tasks / tasks_with_failures`
- `mttr_seconds_avg`: average seconds from first failure to first successful completion for recovered tasks.
- `top_errors`: terminal failed task distribution by error code.

## Error Budget Targets (Default)

- `max_failure_rate`: `0.2`
- `min_retry_success_rate`: `0.6`
- `max_mttr_seconds`: `1800`

These values are configurable in `settings.yaml` under `observability.error_budget`.

## API Surface

- `GET /metrics/workflows/summary`
  - returns reliability summary + error budget evaluation.
- `GET /metrics/workflows/failures`
  - returns recent failure list with classification and recovery status.
