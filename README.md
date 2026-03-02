# AI-Attack

AI-Attack is an enterprise-oriented, AI-assisted automated security testing platform prototype.
It orchestrates LLM reasoning, tool execution, workflow control, governance approval, and evidence reporting into a reproducible engineering pipeline.

> Authorized use only: this project is designed for legal, pre-approved security testing environments.

## Table of Contents

- [Project Scope](#project-scope)
- [Current Status](#current-status)
- [Core Capabilities](#core-capabilities)
- [Architecture Overview](#architecture-overview)
- [Repository Structure](#repository-structure)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Approval Store Backends](#approval-store-backends)
- [API Overview](#api-overview)
- [Testing and Quality Gates](#testing-and-quality-gates)
- [Documentation Index](#documentation-index)
- [Known Limitations](#known-limitations)
- [Roadmap](#roadmap)
- [Security and Legal Notice](#security-and-legal-notice)
- [Contributing](#contributing)

## Project Scope

- AI-driven security workflow: `analyze -> scan -> llm_decide -> verify -> report`
- Governance-first execution: scope control, action allowlist, RBAC, approval workflow
- End-to-end traceability: audit events, evidence artifacts, structured reports
- Engineering-focused operations: retry/recovery, KPI, regression benchmarks, release validation

## Current Status

The project currently includes implemented phases from P0 to P7 with continuous test coverage.

- Workflow orchestration with single-target and multi-stage dependency DAG
- Connectors for `nmap`, `nuclei`, `zaproxy`
- Retest and diff reporting
- DefectDojo integration (optional)
- Observability metrics, KPI export, regression suite
- Approval persistence with pluggable backends and optimistic locking

## Core Capabilities

- LLM decision engine with model routing and cost controls
- Multi-platform target profiling (Linux/Windows strategy hints)
- ScopeGuard + ActionGate for strict pre-execution policy checks
- Human approval flow for high-risk actions
- Approval persistence backends:
  - file (incremental event log)
  - sqlite
  - postgres
- Unified audit evidence:
  - event/input/output artifacts
  - append-only index
  - query and retention APIs
- Report generation:
  - JSON
  - Markdown
  - optional PDF
  - path graph and retest diff reports

## Architecture Overview

```text
Client/API
  -> Security Gate (ScopeGuard, ActionGate, RBAC, Approval)
  -> Workflow Engine (LangGraph/Temporal)
  -> Tool Orchestration (nmap/nuclei/zap)
  -> LLM Decision Engine (routing, cache, budget)
  -> Reporting (report, diff, path view)
  -> Observability (metrics, KPI, regression)
  -> Audit & Evidence Store
```

Key design references:

- [Architecture](docs/architecture.md)
- [Evidence Schema](docs/evidence_schema.md)
- [Security Governance](docs/security_governance.md)

## Repository Structure

```text
backend/      FastAPI service, APIs, config, security, workflow, observability
agents/       Workflow graph, LLM decision engine, profiling, orchestration
connectors/   Security tool adapters and scan orchestrator
policies/     Scope and action governance policies
workflows/    Workflow and strategy YAML definitions
reports/      Structured report generators and schemas
infra/        Release manifest and release validator
tests/        Unit/integration/regression tests
docs/         Architecture, governance, operations, acceptance docs
```

## Quick Start

### 1) Prerequisites

- Python `>=3.11`
- Recommended tools in PATH:
  - `nmap`
  - `nuclei`
  - `zap.bat` (Windows) or `zap.sh` (Linux/macOS)
- Optional (advanced features):
  - Temporal server
  - PostgreSQL

### 2) Install

```bash
python -m venv .venv
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
pip install -e .[dev]
```

### 3) Configure

```bash
copy .env.example .env
```

Edit `settings.yaml` as needed.

### 4) Run API

```bash
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Health check:

```bash
curl http://127.0.0.1:8000/health
```

## Configuration

Primary config file: `settings.yaml`.

Common sections:

- `auth.*`: actor/role headers and RBAC behavior
- `security.*`: scope policy, action policy, approval store backend
- `tools.*`: scanner binary and timeout settings
- `llm.*`: model provider/routing/cache/cost budget
- `workflow.*`: workflow engine, retry, quota, strategy paths
- `audit.*`: evidence root, index writing, retention
- `reporting.*`: report output directories and PDF switch
- `observability.*`: error budgets and KPI windows
- `integrations.defectdojo.*`: external vulnerability platform sync

## Approval Store Backends

Approval storage is pluggable via `security.approval_store`:

```yaml
security:
  approval_store:
    backend: file        # file | sqlite | postgres
    file_path: workflow/approvals/approvals.jsonl
    sqlite_path: workflow/approvals/approvals.db
    postgres_dsn: ""
    table: approval_records
```

Behavior:

- Incremental writes
- Optimistic lock with `version`
- Compare-and-set update on decision transitions

Legacy compatibility:

- `security.approval_store_path` is still honored as default `file_path`

## API Overview

### Security & Governance

- `POST /actions/validate`
- `GET /approvals`
- `GET /approvals/{approval_id}`
- `POST /approvals/{approval_id}/decision`

### Workflow

- `POST /workflows/poc/run`
- `POST /workflows/poc/start`
- `GET /workflows/poc/status/{workflow_id}`
- `GET /workflows/poc/result/{workflow_id}`
- `POST /workflows/poc/cancel/{workflow_id}`
- `POST /workflows/multi-stage/run`

### Task Lifecycle

- `GET /tasks/{task_id}/snapshots`
- `GET /tasks/{task_id}/snapshots/{version}`
- `POST /tasks/{task_id}/resume`
- `POST /tasks/{task_id}/replay`
- `POST /tasks/{task_id}/retest`

### Audit & Operations

- `GET /audit/events?trace_id=<id>`
- `GET /audit/events?task_id=<id>`
- `POST /audit/retention/prune?dry_run=true|false`
- `GET /metrics/workflows/summary`
- `GET /metrics/workflows/failures`
- `GET /metrics/workflows/cost`
- `GET /metrics/kpi/summary?period=weekly|monthly`
- `POST /metrics/kpi/export?period=weekly|monthly`

## Testing and Quality Gates

Run unit/integration tests:

```bash
pytest -q
```

Run regression suite:

```bash
python -m tests.regression.runner \
  --benchmark-dir tests/regression/benchmarks \
  --output-dir tests/regression/results \
  --policy-path tests/regression/benchmarks/policy.yaml
```

Run release readiness validation:

```bash
python -m infra.release_validator --base-dir . --manifest infra/release_manifest.yaml
```

## Documentation Index

- [Architecture](docs/architecture.md)
- [Evidence Schema](docs/evidence_schema.md)
- [Security Governance](docs/security_governance.md)
- [Secrets Policy](docs/secrets_policy.md)
- [Cost Control](docs/cost_control.md)
- [Error Taxonomy](docs/error_taxonomy.md)
- [Retry and Compensation](docs/retry_and_compensation.md)
- [DefectDojo Integration](docs/integration_defectdojo.md)
- [KPI Definition](docs/kpi_definition.md)
- [Release Checklist](docs/release_checklist.md)
- [Demo Playbook](docs/demo_playbook.md)
- [Acceptance Report Template](docs/acceptance_report_template.md)

## Known Limitations

- PostgreSQL backend logic is implemented, but requires environment-specific integration testing before production use.
- Real-world scanner behavior depends on target environment quality and external tool versions.
- This is a production-oriented prototype, not yet a turnkey SaaS product.

## Roadmap

- Harden approval store operations for distributed production clusters
- Expand multi-target scenario orchestration and failure injection testing
- Improve connector coverage for post-exploitation and credential attack simulation (authorized labs only)
- Strengthen CI/CD and packaging/release automation

## Security and Legal Notice

- Use only in environments where you have explicit written authorization.
- Do not use this project against public or third-party systems without permission.
- The maintainers and contributors are not responsible for misuse.

## Contributing

Contributions are welcome for:

- architecture hardening
- connector quality improvements
- workflow reliability and observability
- testing and release automation

Before submitting changes:

1. run `pytest -q`
2. ensure release validation passes
3. keep governance and auditability intact

No open-source license file is currently included. Define a license before public redistribution.
