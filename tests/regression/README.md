# Regression Benchmarks

This directory provides baseline benchmark cases and the regression runner.

## Files

- `benchmarks/*.yaml`: benchmark case definitions
- `benchmarks/policy.yaml`: allowed KPI drop thresholds
- `runner.py`: benchmark execution and baseline comparison runner

## Run

```bash
python -m tests.regression.runner \
  --benchmark-dir tests/regression/benchmarks \
  --output-dir tests/regression/results \
  --baseline-path tests/regression/baseline_summary.json \
  --policy-path tests/regression/benchmarks/policy.yaml
```

Write/refresh baseline:

```bash
python -m tests.regression.runner --write-baseline
```
