# Release Checklist

## Scope

This checklist is used before publishing a demo/release build.

## 1. Functional Gates

1. Core APIs are reachable:
   - `/health`
   - `/workflows/poc/run`
   - `/workflows/multi-stage/run`
   - `/metrics/workflows/summary`
   - `/metrics/kpi/summary`
2. Security governance paths verified:
   - scope deny behavior
   - high-risk approval flow
   - audit event query and retention API
3. Multi-stage path view output generated:
   - `path_graph`
   - `path_view`
   - `path_artifacts`

## 2. Quality Gates

1. Unit/integration tests pass:
   - `pytest -q`
2. Regression suite executed:
   - `python -m tests.regression.runner`
3. No KPI baseline regression beyond policy thresholds.

## 3. Security and Compliance Gates

1. Redaction is enabled (`security.redaction.enabled=true`).
2. Secrets are sourced via managed config/environment, not hardcoded.
3. Retention policy configured and dry-run validated.
4. RBAC defaults and approval signing key configured for target environment.

## 4. Artifact Gates

1. Structured reports generated for PoC/retest/path view.
2. Evidence index and event directories are complete and queryable.
3. KPI export artifacts are generated for weekly/monthly windows.

## 5. Final Validation

Use release validator:

```bash
python -m infra.release_validator --base-dir . --manifest infra/release_manifest.yaml
```

Optional full command execution:

```bash
python -m infra.release_validator --execute-commands
```
