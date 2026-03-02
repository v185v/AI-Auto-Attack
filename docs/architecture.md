# Architecture (P0 Baseline)

## Layered Design

1. API Layer (`backend/api`)
   - HTTP entrypoints
   - request validation and response shaping
2. Orchestration Layer (`agents`, `workflows`)
   - planning, decision, and workflow control
3. Execution Layer (`connectors`)
   - standardized adapters to security tools
4. Governance Layer (`policies`, `backend/security`)
   - scope control, action gating, approvals, audit
5. Evidence and Reporting Layer (`backend/audit`, `reports`, storage)
   - structured artifacts and reproducible evidence

## Baseline Runtime Flow

1. Client sends task request.
2. Scope and action policies are checked.
3. Workflow engine dispatches the next node.
4. Connector executes approved tool command.
5. Output is parsed into normalized evidence.
6. Findings are aggregated into report payloads.

## P2-2 State Persistence and Recovery

1. Workflow initialization writes snapshot version `1` for deterministic replay.
2. Each workflow node writes a new state snapshot with:
   - `task_id`, `trace_id`, `step`, `status`, `reason`
   - node input/output
   - full merged workflow state
3. Task APIs expose state retrieval and recovery:
   - `GET /tasks/{task_id}/snapshots`
   - `GET /tasks/{task_id}/snapshots/{version}`
   - `POST /tasks/{task_id}/resume`
   - `POST /tasks/{task_id}/replay`
4. Resume strategy:
   - if latest snapshot is terminal failed `build_report`, resume from previous executable node
   - clears failed runtime status before continuation, then proceeds to report generation
5. Replay strategy:
   - load initial snapshot and execute full graph from start

## P2-3 Failure Taxonomy and Reliability Metrics

1. Failures are normalized into a stable taxonomy:
   - code, category, severity, retriable
2. Reliability metrics are computed from workflow snapshots:
   - failure rate
   - retry success rate
   - MTTR
   - top terminal error codes
3. Error budget evaluation compares runtime metrics against configurable targets.
4. Read-only metrics APIs expose operational posture for dashboards and alerts:
   - `GET /metrics/workflows/summary`
   - `GET /metrics/workflows/failures`

## P3-1 Target Profiling

1. Target profiler consumes:
   - input target format (IP/hostname/URL)
   - scan-derived open port and service fingerprints
2. Profiling output:
   - `os_guess` with confidence
   - `strategy_hint` for later branch selection
   - normalized service exposure summary
3. Integration points:
   - `analyze_target`: initial profile from target metadata
   - `scan_target`: profile refinement from scan evidence
   - `llm_decide`: profile injected into decision context

## P3-2 Platform Strategy Branching

1. Strategy files define Linux/Windows branch policies:
   - `workflows/strategy_linux.yaml`
   - `workflows/strategy_windows.yaml`
2. Scan orchestrator selects branch using:
   - `strategy_hint` from target profiler
   - fallback by `os_guess`
   - fallback to generic branch
3. Branch execution behavior:
   - baseline service discovery through `nmap`
   - optional web checks (`nuclei`, `zaproxy`) only when web signals exist
4. Strategy selection is persisted in workflow state and reports through `scan.strategy`.

## P4-1 Vulnerability Platform Integration (DefectDojo)

1. Report stage integration connector uploads generated JSON report to DefectDojo:
   - endpoint: `/api/v2/import-scan/`
   - scan metadata includes engagement, severity threshold, tags, and task/trace labels
2. Workflow persists synchronization result:
   - `defectdojo_sync.status`
   - `defectdojo_sync.http_status`
   - `defectdojo_sync.import_id` (when returned)
3. Audit trail is extended with a dedicated sync event:
   - `action=workflow_sync_defectdojo`
   - `tool=defectdojo_connector`
4. Optional lifecycle API helper supports finding status transitions:
   - `new`, `fixed`, `retest_failed`, `closed`

## P4-2 Retest and Before/After Diff

1. Retest entrypoint is task-based:
   - `POST /tasks/{task_id}/retest`
2. Retest execution loads baseline task/report state and derives focus scope:
   - focus findings (verified/high-confidence first)
   - focus tools (derived from finding tool attribution)
3. Scan stage accepts focused tool replay via `force_tools`, reducing unnecessary full-path reruns.
4. Diff report compares baseline vs retest findings and outputs:
   - resolved findings
   - newly introduced findings
   - persistent findings
5. Retest state is persisted as a new task lineage with explicit linkage:
   - `source_task_id`
   - `retest_task_id`
   - `diff_report` and `diff_artifacts`

## P5-1 RBAC and Approval Governance

1. API-layer RBAC enforces role-based permissions:
   - `admin`, `auditor`, `executor`
2. Security endpoints require explicit permissions:
   - action validation
   - approval reading
   - approval decision
3. Approval decisions are tamper-evident with stored signatures:
   - `decision_signature`
   - append-only `decision_history`
4. Audit operator identity is bound to authenticated actor context.

## P5-2 Secrets and Sensitive Data Governance

1. Secret sourcing is abstracted through a unified manager:
   - environment-backed provider for key resolution
   - logical key mapping for integration and auth signing use cases
2. Artifact redaction is enforced at write boundaries:
   - audit evidence payloads and text outputs
   - workflow reports and retest diff reports
3. Retention policy service provides lifecycle control:
   - date-folder based cleanup for evidence, generated reports, and diff reports
   - supports dry-run planning and real deletion execution
4. Retention execution endpoint is protected by RBAC admin permission:
   - `POST /audit/retention/prune`

## P5-3 Cost and Performance Control

1. Model routing layer selects model tier by risk context:
   - high-risk findings route to high-capability model
   - low-risk findings route to low-cost model
2. Decision cache prevents repeated LLM calls for identical decision contexts:
   - hash-keyed payload deduplication
   - TTL + max-size bounded cache
3. Decision runtime metadata is persisted for monitoring:
   - estimated tokens, estimated cost, latency, cache-hit, route path
4. Cost observability API exposes operational posture:
   - `GET /metrics/workflows/cost`
   - cost and latency budget breach evaluation

## P6-1 Multi-Node Orchestration and Quota

1. Multi-stage workflow runner executes dependency DAG nodes using the existing single-target workflow engine.
2. Node-level behavior:
   - explicit `depends_on` ordering
   - priority-based scheduling
   - deterministic execution order with bounded parallel windows
3. Failure handling:
   - dependent nodes are skipped when upstream dependencies fail (strict mode)
   - optional `continue_on_error` supports degraded continuation paths
4. Resource controls:
   - target count cap per run
   - max parallel task cap via resource quota manager
5. Entry API:
   - `POST /workflows/multi-stage/run`

## P6-2 Attack Path Correlation

1. Multi-stage execution outputs are transformed into a dependency path graph:
   - nodes: target, status, findings, stage tag, risk score
   - edges: dependency flow between staged targets
2. Path extraction computes end-to-end chains from root to leaf:
   - `initial_exposure -> lateral_movement -> business_impact`
3. Path report generation persists structured artifacts:
   - machine-readable JSON for automation and query
   - Markdown view for human interpretation and review
4. Multi-stage API response now includes:
   - `path_graph`
   - `path_view`
   - `path_artifacts`

## P7-1 KPI and Periodic Governance Export

1. KPI job service aggregates weekly/monthly operational posture from:
   - workflow snapshots
   - reliability and cost summaries
   - audit approval events
2. KPI dimensions:
   - coverage quality (`coverage_rate`, `false_positive_rate`)
   - retest quality (`reproducibility_rate`, `closure_cycle_seconds_avg`)
   - operational cost (`single_task_cost_usd_avg`)
   - governance latency (`approval_lead_time_seconds_avg`)
3. APIs:
   - `GET /metrics/kpi/summary`
   - `POST /metrics/kpi/export`
4. Export artifacts:
   - JSON and Markdown KPI reports for weekly/monthly review.

## P7-2 Regression Benchmark and Baseline Guard

1. Regression benchmark suite stores scenario definitions in YAML:
   - benchmark target/workflow metadata
   - expected status and minimum quality thresholds
2. Runner executes benchmark cases and collects suite-level quality KPIs:
   - coverage rate
   - reproducibility rate
   - stability rate
3. Baseline guard compares current run metrics to previous baseline with allowed-drop policy.
4. Regression run artifacts are exported as JSON/Markdown for release gating and audit.

## Release Readiness Layer

1. Release manifest defines required project assets and mandatory validation commands.
2. Release validator performs:
   - path completeness checks
   - optional command execution checks
   - JSON/Markdown release report generation
3. Final handoff documents:
   - release checklist
   - demo playbook
   - acceptance report template

## P0 Status

- Project structure initialized.
- Base config and policy templates ready.
- Minimal health API available for runtime validation.
- Audit event model and evidence persistence integrated in security flow.
- P1 minimal LangGraph workflow added (`agents/workflow_graph.py`) with node-level audit recording.
- P1-2 real connector orchestration added (`connectors/scan_orchestrator.py`) for Nmap/Nuclei/ZAP execution.
- P1-3 LLM decision engine added (`agents/decision_engine.py`) with structured JSON output and prompt templates.
- P1-4 report generator added (`reports/generator.py`) for JSON + Markdown (+ optional PDF) artifact generation.
- P2-1 Temporal integration added (`backend/workflow/temporal_worker.py`) with retry policy, timeout controls, and compensation activity.
- P2-2 state store and recovery APIs added (`backend/workflow/state_store.py`, `backend/api/tasks.py`) with snapshot query + resume/replay support.
- P2-3 observability layer added (`backend/observability/metrics.py`, `backend/api/metrics.py`) with taxonomy, error budget, and reliability metrics.
- P3-1 target profiler added (`agents/target_profiler.py`) with OS guess confidence and workflow-level strategy hints.
- P3-2 strategy branching added (`workflows/strategy_linux.yaml`, `workflows/strategy_windows.yaml`, `connectors/scan_orchestrator.py`) with automatic Linux/Windows path selection.
- P4-1 DefectDojo connector added (`connectors/defectdojo_connector.py`) with report sync and lifecycle update capability.
- P4-2 retest flow added (`workflows/retest.yaml`, `/tasks/{task_id}/retest`, `reports/diff_generator.py`) with focused replay and before/after diff artifacts.
- P5-1 RBAC layer added (`backend/auth/rbac.py`, `docs/security_governance.md`) with approval-decision signature recording.
- P5-2 sensitive data governance added (`backend/security/redaction.py`, `backend/security/secrets_manager.py`, `backend/audit/retention.py`, `docs/secrets_policy.md`) with redaction, secret abstraction, and retention APIs.
- P5-3 cost control added (`agents/model_router.py`, `docs/cost_control.md`, `/metrics/workflows/cost`) with model routing, decision dedup cache, and runtime cost telemetry.
- P6-1 multi-stage workflow added (`agents/multi_stage_workflow.py`, `backend/scheduler/resource_quota.py`, `workflows/multi_stage.yaml`) with dependency orchestration and quota enforcement.
- P6-2 path correlation added (`backend/analysis/path_graph.py`, `reports/path_view_generator.py`, `reports/path_view.md`) with chain-level risk view and persisted path artifacts.
- P7-1 KPI system added (`backend/observability/kpi_jobs.py`, `docs/kpi_definition.md`, `/metrics/kpi/*`) with periodic summary and export capability.
- P7-2 regression suite added (`tests/regression/benchmarks/*.yaml`, `tests/regression/runner.py`) with baseline comparison and KPI drop guardrails.
- Release toolkit added (`infra/release_manifest.yaml`, `infra/release_validator.py`, `docs/release_checklist.md`) for pre-release validation and formal acceptance handoff.
