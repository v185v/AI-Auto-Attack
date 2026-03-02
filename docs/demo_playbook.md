# Demo Playbook

## 1. Environment Preparation

1. Install dependencies:
   - `pip install -e .[dev]`
2. Verify settings:
   - `settings.yaml`
3. Start API:
   - `uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000`

## 2. Demo Sequence

1. Health check:
   - `GET /health`
2. Single-target run:
   - `POST /workflows/poc/run`
3. Multi-stage dependency run:
   - `POST /workflows/multi-stage/run`
4. Verify path correlation output:
   - check `path_graph`, `path_view`, `path_artifacts`
5. KPI view:
   - `GET /metrics/kpi/summary?period=weekly`
6. KPI export:
   - `POST /metrics/kpi/export?period=weekly`
7. Regression runner:
   - `python -m tests.regression.runner`

## 3. Demo Evidence Collection

1. Report artifacts:
   - `reports/generated`
   - `reports/diff`
   - `reports/path`
2. Audit evidence:
   - `evidence/audit-events.jsonl`
   - `evidence/<date>/<trace_id>/<event_id>/`
3. KPI artifacts:
   - `observability/kpi`
4. Regression artifacts:
   - `tests/regression/results`

## 4. Demo Exit Criteria

1. End-to-end workflow execution completes.
2. Governance controls are visibly enforced.
3. Structured evidence and reports are generated.
4. KPI and regression reports are exported.
