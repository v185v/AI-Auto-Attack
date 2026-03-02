from __future__ import annotations

import json
from pathlib import Path

import yaml

from tests.regression.runner import (
    BenchmarkCase,
    compare_with_baseline,
    load_benchmarks,
    load_regression_policy,
    run_regression_suite,
)


def test_load_benchmarks_and_policy(tmp_path) -> None:
    benchmark_dir = tmp_path / "benchmarks"
    benchmark_dir.mkdir(parents=True, exist_ok=True)
    (benchmark_dir / "policy.yaml").write_text(
        yaml.safe_dump(
            {
                "max_coverage_drop": 0.1,
                "max_reproducibility_drop": 0.2,
                "max_stability_drop": 0.15,
            }
        ),
        encoding="utf-8",
    )
    (benchmark_dir / "case-a.yaml").write_text(
        yaml.safe_dump(
            {
                "id": "case-a",
                "workflow": "poc_single_target",
                "target": "10.20.1.8",
                "expected": {
                    "status": "completed",
                    "min_finding_count": 1,
                },
            }
        ),
        encoding="utf-8",
    )

    cases = load_benchmarks(benchmark_dir)
    policy = load_regression_policy(benchmark_dir / "policy.yaml")

    assert len(cases) == 1
    assert isinstance(cases[0], BenchmarkCase)
    assert cases[0].case_id == "case-a"
    assert policy.max_coverage_drop == 0.1


def test_run_regression_suite_with_baseline_comparison(tmp_path) -> None:
    benchmark_dir = tmp_path / "benchmarks"
    result_dir = tmp_path / "results"
    baseline_path = tmp_path / "baseline.json"
    policy_path = benchmark_dir / "policy.yaml"
    benchmark_dir.mkdir(parents=True, exist_ok=True)

    (policy_path).write_text(
        yaml.safe_dump(
            {
                "max_coverage_drop": 0.05,
                "max_reproducibility_drop": 0.05,
                "max_stability_drop": 0.05,
            }
        ),
        encoding="utf-8",
    )
    (benchmark_dir / "case-ok.yaml").write_text(
        yaml.safe_dump(
            {
                "id": "case-ok",
                "workflow": "poc_single_target",
                "target": "10.20.1.8",
                "expected": {
                    "status": "completed",
                    "min_finding_count": 1,
                    "min_verified_findings": 1,
                },
            }
        ),
        encoding="utf-8",
    )
    (benchmark_dir / "case-scope.yaml").write_text(
        yaml.safe_dump(
            {
                "id": "case-scope",
                "workflow": "poc_single_target",
                "target": "172.16.10.8",
                "expected": {
                    "status": "failed",
                    "allow_failure_reasons": ["scope_denied:"],
                },
            }
        ),
        encoding="utf-8",
    )

    baseline_path.write_text(
        json.dumps(
            {
                "metrics": {
                    "coverage_rate": 0.9,
                    "reproducibility_rate": 1.0,
                    "stability_rate": 1.0,
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )

    def executor(case: BenchmarkCase) -> dict:
        if case.case_id == "case-ok":
            return {
                "status": "completed",
                "scan": {"finding_count": 1},
                "verification": {"verified_findings": 1},
            }
        return {
            "status": "failed",
            "failure_reason": "scope_denied:target_out_of_scope",
            "scan": {"finding_count": 0},
            "verification": {"verified_findings": 0},
        }

    summary = run_regression_suite(
        benchmark_dir=benchmark_dir,
        output_dir=result_dir,
        baseline_path=baseline_path,
        policy_path=policy_path,
        executor=executor,
    )
    assert summary["status"] == "failed"
    assert summary["comparison"]["status"] == "regressed"
    assert summary["comparison"]["regressions"][0]["metric"] == "coverage_rate"
    assert Path(summary["artifacts"]["json_path"]).exists()
    assert Path(summary["artifacts"]["markdown_path"]).exists()


def test_compare_with_baseline_healthy() -> None:
    comparison = compare_with_baseline(
        current={"coverage_rate": 0.8, "reproducibility_rate": 0.7, "stability_rate": 0.9},
        baseline={"coverage_rate": 0.82, "reproducibility_rate": 0.72, "stability_rate": 0.9},
        policy=load_regression_policy(None),
    )
    assert comparison["status"] == "healthy"
    assert comparison["regressions"] == []
