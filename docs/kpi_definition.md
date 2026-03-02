# KPI Definition (P7-1)

## Objective

Define operational KPIs for weekly/monthly governance and provide automated export artifacts.

## KPI Metrics

1. `coverage_rate`
- Formula: `tasks_with_findings / total_tasks`
- Meaning: proportion of executed tasks that produced actionable findings.

2. `false_positive_rate`
- Formula: `(total_findings - verified_findings) / total_findings`
- Meaning: estimated false-positive pressure in current detection output.

3. `reproducibility_rate`
- Formula: `reproduced_retests / total_retests`
- Meaning: proportion of retest tasks where previously discovered paths/findings are still reproducible.

4. `closure_cycle_seconds_avg`
- Formula: average `(retest_completed_time - source_task_start_time)`
- Meaning: average elapsed cycle from baseline discovery to retest closure stage.

5. `single_task_cost_usd_avg`
- Source: cost observability summary (`avg_estimated_cost_per_task_usd`)
- Meaning: average estimated LLM cost per workflow task.

6. `approval_lead_time_seconds_avg`
- Formula: average `(approval_decision_time - approval_request_time)`
- Meaning: governance latency from approval request to decision.

## KPI Jobs

Implemented module:
- `backend/observability/kpi_jobs.py`

Supported periods:
- `weekly`
- `monthly`

Data sources:
- workflow state snapshots
- workflow metrics summaries
- audit event index + evidence payloads

## API Endpoints

- `GET /metrics/kpi/summary?period=weekly|monthly`
- `POST /metrics/kpi/export?period=weekly|monthly`

## Export Artifacts

Output directory (configurable):
- `observability.kpi.output_dir`

Generated files:
- `kpi_summary.json`
- `kpi_summary.md`

Default path pattern:
- `<output_dir>/<date>/<period-run-id>/kpi_summary.json`
- `<output_dir>/<date>/<period-run-id>/kpi_summary.md`
