# AI-Attack

Enterprise AI-assisted automated security testing project scaffold (P0).

## Scope

This project is designed for authorized security testing only.

## Project Structure

```
backend/      FastAPI service, APIs, config, security guards
agents/       Agent planning and decision components
connectors/   Tool adapters (nmap, nuclei, zap, etc.)
policies/     Scope and action governance policies
workflows/    Workflow definitions
reports/      Structured report schemas and generators
infra/        Deployment and infrastructure references
tests/        Unit and integration tests
docs/         Architecture and implementation documents
```

## Quick Start

1. Create a virtual environment:
   - `python -m venv .venv`
2. Activate it:
   - PowerShell: `.\\.venv\\Scripts\\Activate.ps1`
3. Install dependencies:
   - `pip install -e .[dev]`
4. Prepare runtime config:
   - Copy `.env.example` to `.env`
5. Run service:
   - `uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000`
6. Health check:
   - `GET http://127.0.0.1:8000/health`

## P0 Security Endpoints

- `POST /actions/validate`
  - validates scope policy + action gate policy
  - blocks out-of-scope targets
  - blocks high-risk actions until approval is granted
- `GET /approvals`
- `GET /approvals/{approval_id}`
- `POST /approvals/{approval_id}/decision`
  - request body: `{"status":"approved|rejected","approver":"name"}`

## P1 Workflow Endpoint

- `POST /workflows/poc/run`
  - runs minimal LangGraph workflow:
    - analyze -> scan (nmap + nuclei + zap) -> verify -> report
  - returns `completed` or `failed` with `failure_reason` when failed
  - each node writes audit evidence

## P1-2 Connector Execution

- Scan stage now executes real commands through unified connectors:
  - `nmap`
  - `nuclei`
  - `zap` (`zap.bat` on Windows, `zap.sh` on Linux/macOS)
- ActionGate allowlist is enforced before each tool command execution.
- Required binaries must be installed and accessible in `PATH` or configured via `settings.yaml`.

## P1-3 LLM Decision Engine

- Added structured decision engine:
  - `agents/decision_engine.py`
  - prompt templates under `agents/prompts/`
- Workflow now includes an `llm_decide` node between scan and verify.
- Decision output schema includes:
  - `target_profile`
  - `risk_hypotheses`
  - `next_actions`
  - `evidence_interpretation`
- Enable LLM mode in `settings.yaml`:
  - `llm.enabled: true`
  - `llm.default_model`: e.g. `openai/gpt-4.1-mini`, `anthropic/claude-3-5-sonnet-latest`, `deepseek/deepseek-chat`
  - provide corresponding API keys in `.env`

## P1-4 Structured Report Generator

- Added report generator:
  - `reports/generator.py`
  - `reports/report_schema.json`
- Workflow report node now writes artifacts to disk:
  - machine-readable JSON report
  - human-readable Markdown report
  - optional PDF (if `reportlab` installed and `reporting.enable_pdf=true`)
- Config:
  - `reporting.output_dir`: output root directory (default `reports/generated`)
  - `reporting.enable_pdf`: enable optional PDF export

## P2-1 Temporal Workflow Engine

- Async workflow endpoints:
  - `POST /workflows/poc/start`
  - `GET /workflows/poc/status/{workflow_id}`
  - `GET /workflows/poc/result/{workflow_id}`
  - `POST /workflows/poc/cancel/{workflow_id}`
- Temporal worker entrypoint:
  - `python -m backend.workflow.temporal_worker`
- To enable:
  - `settings.yaml -> workflow.temporal.enabled: true`
  - configure Temporal address/namespace/task queue
- Retry and compensation spec:
  - `docs/retry_and_compensation.md`

## P2-2 Workflow State Snapshot + Resume/Replay

- File-based workflow state snapshots:
  - configured via `settings.yaml -> workflow.state_store.directory`
  - default directory: `workflow/state`
  - each task stores append-only snapshots in:
    - `<state_dir>/<task_id>/snapshots.jsonl`
    - `<state_dir>/<task_id>/meta.json`
- Task lifecycle APIs:
  - `GET /tasks/{task_id}/snapshots`
  - `GET /tasks/{task_id}/snapshots/{version}`
  - `POST /tasks/{task_id}/resume`
  - `POST /tasks/{task_id}/replay`
- Resume behavior:
  - resumes from the latest executable step (skips terminal failed `build_report` snapshot)
  - keeps same `task_id`/`trace_id` for full traceability
- Replay behavior:
  - re-runs workflow from initial snapshot state for the same task

## P2-3 Error Taxonomy and Error Budget

- Added unified failure classification and reliability metrics:
  - `backend/observability/metrics.py`
  - `docs/error_taxonomy.md`
- Metrics APIs:
  - `GET /metrics/workflows/summary?window_hours=168`
  - `GET /metrics/workflows/failures?window_hours=168&limit=50`
- Summary output includes:
  - `failure_rate`
  - `retry_success_rate`
  - `mttr_seconds_avg`
  - `top_errors`
  - `error_budget` (healthy/breached + threshold breaches)
- Config:
  - `observability.default_window_hours`
  - `observability.error_budget.max_failure_rate`
  - `observability.error_budget.min_retry_success_rate`
  - `observability.error_budget.max_mttr_seconds`

## P3-1 Target Environment Identification

- Added target profiling module:
  - `agents/target_profiler.py`
- Workflow now produces a structured `target_profile`:
  - target type (`ip` / `hostname` / `url`)
  - OS guess (`linux` / `windows` / `unknown`)
  - confidence score (`os_confidence`)
  - strategy hint (`strategy_linux` / `strategy_windows` / `strategy_generic`)
  - extracted open ports and exposed services from scan outputs
- `target_profile` is attached in:
  - `analysis.target_profile`
  - top-level workflow state (`target_profile`)
  - LLM decision context (for downstream strategy selection)

## P3-2 Platform Strategy Branching

- Added strategy definition files:
  - `workflows/strategy_linux.yaml`
  - `workflows/strategy_windows.yaml`
- Scan orchestration now auto-selects branch by:
  - `target_profile.strategy_hint` (preferred)
  - fallback `target_profile.os_guess`
  - fallback generic strategy
- Branch behavior:
  - Linux/Windows branch default runs `nmap`
  - auto-adds `nuclei` + `zaproxy` when web signals are present
- Workflow output now includes selected scan strategy:
  - `scan.strategy.key`
  - `scan.strategy.enabled_tools`
- Config:
  - `workflow.strategies.linux_path`
  - `workflow.strategies.windows_path`

## P4-1 DefectDojo Integration

- Added DefectDojo connector:
  - `connectors/defectdojo_connector.py`
- Workflow report stage now supports automatic sync:
  - uploads report JSON via `POST /api/v2/import-scan/`
  - records sync result in workflow state as `defectdojo_sync`
  - writes audit event `workflow_sync_defectdojo`
- Report artifact now includes integration status:
  - `integrations.defectdojo`
- Optional lifecycle helper for finding status transitions:
  - `new`, `fixed`, `retest_failed`, `closed`
- Config:
  - `integrations.defectdojo.enabled`
  - `integrations.defectdojo.base_url`
  - `integrations.defectdojo.api_token`
  - `integrations.defectdojo.engagement_id`
  - `integrations.defectdojo.scan_type`
  - `integrations.defectdojo.minimum_severity`
  - `integrations.defectdojo.verify_ssl`
  - `integrations.defectdojo.timeout_seconds`
  - `integrations.defectdojo.default_tags`
- Integration guide:
  - `docs/integration_defectdojo.md`

## P4-2 Retest Workflow and Diff Report

- Added retest workflow definition:
  - `workflows/retest.yaml`
- Added retest diff report generator:
  - `reports/diff_generator.py`
- New task API:
  - `POST /tasks/{task_id}/retest`
  - behavior:
    - loads baseline task/report
    - derives focus findings/tools
    - runs focused retest workflow with a new `task_id`
    - generates before/after diff report (`diff_report`, `diff_artifacts`)
- Retest output fields:
  - `source_task_id`
  - `retest_task_id`
  - `retest_context.focus_findings`
  - `retest_context.focus_tools`
  - `diff_report.summary.{resolved_count,new_count,persistent_count}`
- Config:
  - `reporting.diff_output_dir`

## P5-1 RBAC and Approval Governance

- Added RBAC module:
  - `backend/auth/rbac.py`
- Role model:
  - `admin`
  - `auditor`
  - `executor`
- Security APIs now enforce role permissions for:
  - action validation
  - approval query
  - approval decision
- Approval decisions now include signed records:
  - `decision_signature`
  - `decision_history[]`
- Config:
  - `auth.enabled`
  - `auth.header_user`
  - `auth.header_role`
  - `auth.default_user`
  - `auth.default_role`
  - `auth.enforce_headers`
  - `auth.approval_signing_key`
- Governance reference:
  - `docs/security_governance.md`

### Approval Store Backends

- Approval records now support pluggable persistent backends:
  - `file` (default)
  - `sqlite`
  - `postgres`
- Record persistence model:
  - incremental writes (append-style for file backend, row-level updates for DB backends)
  - optimistic lock via `version` field on each approval record
  - `create` starts at `version=1`; state transition updates increment version
- Config path:
  - `security.approval_store.backend`
  - `security.approval_store.file_path`
  - `security.approval_store.sqlite_path`
  - `security.approval_store.postgres_dsn`
  - `security.approval_store.table`
- Legacy compatibility:
  - `security.approval_store_path` is still honored as default `file_path`.

## P5-2 Secrets and Sensitive Data Governance

- Added secret manager abstraction:
  - `backend/security/secrets_manager.py`
  - current provider: environment variables (`secrets.provider=env`)
- Added unified redaction module:
  - `backend/security/redaction.py`
  - audit evidence, workflow reports, and diff reports are redacted before write
- Added retention cleanup service:
  - `backend/audit/retention.py`
  - date-folder based retention for evidence and reports
- New audit retention API:
  - `POST /audit/retention/prune?dry_run=true|false`
  - admin-only permission: `retention:prune`
- Config:
  - `security.redaction.enabled`
  - `security.redaction.mask`
  - `security.redaction.sensitive_keys`
  - `secrets.provider`
  - `secrets.env_prefix`
  - `secrets.env_mapping`
  - `audit.retention.enabled`
  - `audit.retention.evidence_days`
  - `audit.retention.reports_days`
- Policy reference:
  - `docs/secrets_policy.md`

## P5-3 Cost and Performance Control

- Added model router and dedup cache:
  - `agents/model_router.py`
  - risk-based model tier routing (`high_capability` / `low_cost`)
  - TTL + bounded cache for repeated decision contexts
- Integrated into LLM decision stage:
  - `agents/decision_engine.py`
  - route trace + runtime telemetry (`llm_runtime`) attached to decision output
- Added cost observability endpoint:
  - `GET /metrics/workflows/cost?window_hours=168`
  - aggregates estimated LLM cost, latency, cache hit ratio, per-model split
- Config:
  - `llm.routing.*`
  - `llm.cost.*`
- Governance reference:
  - `docs/cost_control.md`

## P6-1 Multi-Stage Workflow and Resource Quota

- Added multi-stage orchestration runner:
  - `agents/multi_stage_workflow.py`
  - supports dependency DAG execution, node priority, and fail/skip propagation
- Added resource quota manager:
  - `backend/scheduler/resource_quota.py`
  - enforces max targets per run and max parallel task windows
- Added multi-stage API:
  - `POST /workflows/multi-stage/run`
- Added sample multi-stage workflow definition:
  - `workflows/multi_stage.yaml`
- Config:
  - `workflow.resource_quota.enabled`
  - `workflow.resource_quota.max_parallel_tasks`
  - `workflow.resource_quota.max_targets_per_run`

## P6-2 Attack Path Correlation Analysis

- Added path graph analysis module:
  - `backend/analysis/path_graph.py`
  - correlates multi-stage node dependencies into path chains
  - outputs stage chain:
    - `initial_exposure`
    - `lateral_movement`
    - `business_impact`
- Added path view report generator:
  - `reports/path_view_generator.py`
  - outputs JSON + Markdown artifacts
- Added path view specification:
  - `reports/path_view.md`
- Multi-stage workflow now returns:
  - `path_graph`
  - `path_view`
  - `path_artifacts`
- Config:
  - `reporting.path_output_dir`

## P7-1 KPI System and Periodic Export

- Added KPI job service:
  - `backend/observability/kpi_jobs.py`
- Added KPI APIs:
  - `GET /metrics/kpi/summary?period=weekly|monthly`
  - `POST /metrics/kpi/export?period=weekly|monthly`
- KPI outputs include:
  - coverage rate
  - false positive rate
  - reproducibility rate
  - closure cycle average
  - average single-task LLM cost
  - approval lead time average
- Config:
  - `observability.kpi.output_dir`
  - `observability.kpi.weekly_window_hours`
  - `observability.kpi.monthly_window_hours`
- Definition reference:
  - `docs/kpi_definition.md`

## P7-2 Regression Benchmark Suite

- Added benchmark cases and regression runner:
  - `tests/regression/benchmarks/*.yaml`
  - `tests/regression/runner.py`
- Added KPI regression policy thresholds:
  - `tests/regression/benchmarks/policy.yaml`
- Runner capabilities:
  - executes benchmark suite
  - validates per-case expectations
  - computes regression KPI metrics (`coverage/reproducibility/stability`)
  - compares against baseline summary
  - exports JSON + Markdown run reports
- Quick run:
  - `python -m tests.regression.runner`
- Optional baseline update:
  - `python -m tests.regression.runner --write-baseline`
- Reference:
  - `tests/regression/README.md`

## Release Readiness Toolkit

- Release manifest:
  - `infra/release_manifest.yaml`
- Release validator:
  - `python -m infra.release_validator --base-dir . --manifest infra/release_manifest.yaml`
- Release artifacts:
  - JSON + Markdown report under `infra/release_reports/`
- Release docs:
  - `docs/release_checklist.md`
  - `docs/demo_playbook.md`
  - `docs/acceptance_report_template.md`

## Audit and Evidence

- Every `/actions/validate` and approval decision writes an audit event and evidence files:
  - `event.json`
  - `input.json`
  - `output.json`
  - optional `raw_output.txt` and `attachments/`
- Default evidence root: `evidence/` (configurable in `settings.yaml` under `audit.evidence_root`).
- Schema reference: `docs/evidence_schema.md`.
- Query APIs:
  - `GET /audit/events?trace_id=<id>&limit=50&offset=0`
  - `GET /audit/events?task_id=<id>&limit=50&offset=0`
- Retention API:
  - `POST /audit/retention/prune?dry_run=true|false` (admin only)

## P0 Deliverables Included

- Directory skeleton
- Base runtime config templates
- Governance policy templates
- Minimal FastAPI service with health endpoint
- Basic test for service health
